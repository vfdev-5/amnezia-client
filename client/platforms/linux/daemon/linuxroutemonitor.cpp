/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "linuxroutemonitor.h"

#include <QNetworkInterface>
#include <QCoreApplication>
#include <QProcess>
#include <QScopeGuard>
#include <QTimer>

#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include "leakdetector.h"
#include "logger.h"

namespace {
Logger logger("LinuxRouteMonitor");
}  // namespace


typedef struct wg_allowedip {
    uint16_t family;
    union {
        struct in_addr ip4;
        struct in6_addr ip6;
    };
    uint8_t cidr;
    struct wg_allowedip *next_allowedip;
} wg_allowedip;

constexpr const char* WG_INTERFACE = "amn0";

static void nlmsg_append_attr(struct nlmsghdr* nlmsg, size_t maxlen,
                              int attrtype, const void* attrdata,
                              size_t attrlen);
static void nlmsg_append_attr32(struct nlmsghdr* nlmsg, size_t maxlen,
                                int attrtype, uint32_t value);

static bool buildAllowedIp(wg_allowedip* ip, const IPAddress& prefix);


LinuxRouteMonitor::LinuxRouteMonitor(const QString& ifname, QObject* parent)
    : QObject(parent), m_ifname(ifname) {
  MZ_COUNT_CTOR(LinuxRouteMonitor);
  logger.debug() << "LinuxRouteMonitor created.";

  memset(&m_defaultGwIpv4, 0, sizeof(m_defaultGwIpv4));
  memset(&m_defaultGwIpv6, 0, sizeof(m_defaultGwIpv6));

  m_nlsock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
  if (m_nlsock < 0) {
      logger.warning() << "Failed to create netlink socket:" << strerror(errno);
  }

  struct sockaddr_nl nladdr;
  memset(&nladdr, 0, sizeof(nladdr));
  nladdr.nl_family = AF_NETLINK;
  nladdr.nl_pid = getpid();
  // Subscribe to route change notifications (adapted from macOS PF_ROUTE).
  nladdr.nl_groups = RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE;
  if (bind(m_nlsock, (struct sockaddr*)&nladdr, sizeof(nladdr)) != 0) {
      logger.warning() << "Failed to bind netlink socket:" << strerror(errno);
  }

  m_notifier = new QSocketNotifier(m_nlsock, QSocketNotifier::Read, this);
  connect(m_notifier, &QSocketNotifier::activated, this,
          &LinuxRouteMonitor::nlsockReady);

  // Grab the default routes at startup (like macOS rtmFetchRoutes).
  fetchDefaultRoutes();
}

LinuxRouteMonitor::~LinuxRouteMonitor() {
  MZ_COUNT_DTOR(LinuxRouteMonitor);
  flushExclusionRoutes();
  if (m_nlsock >= 0) {
      close(m_nlsock);
  }
  logger.debug() << "LinuxRouteMonitor destroyed.";
}

// Fetch the current default routes from the kernel routing table.
// Uses a separate netlink socket to perform a synchronous dump, similar
// to the macOS rtmFetchRoutes() approach.
void LinuxRouteMonitor::fetchDefaultRoutes() {
    int sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    if (sock < 0) {
        logger.warning() << "Failed to create netlink socket for route fetch:"
                         << strerror(errno);
        return;
    }

    struct sockaddr_nl nladdr;
    memset(&nladdr, 0, sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;
    if (bind(sock, (struct sockaddr*)&nladdr, sizeof(nladdr)) != 0) {
        logger.warning() << "Failed to bind fetch socket:" << strerror(errno);
        close(sock);
        return;
    }

    // Request a dump of all routes.
    struct {
        struct nlmsghdr nlh;
        struct rtmsg rtm;
    } req;
    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.nlh.nlmsg_type = RTM_GETROUTE;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq = 1;
    req.nlh.nlmsg_pid = 0;
    req.rtm.rtm_family = AF_UNSPEC;
    req.rtm.rtm_table = RT_TABLE_MAIN;

    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (send(sock, &req, req.nlh.nlmsg_len, 0) < 0) {
        logger.warning() << "Failed to send route dump request:"
                         << strerror(errno);
        close(sock);
        return;
    }

    // Parse the dump response.
    char buf[8192];
    bool done = false;
    while (!done) {
        ssize_t len = recv(sock, buf, sizeof(buf), 0);
        if (len <= 0) {
            break;
        }

        struct nlmsghdr* nlmsg = (struct nlmsghdr*)buf;
        for (; NLMSG_OK(nlmsg, len); nlmsg = NLMSG_NEXT(nlmsg, len)) {
            if (nlmsg->nlmsg_type == NLMSG_DONE) {
                done = true;
                break;
            }
            if (nlmsg->nlmsg_type == NLMSG_ERROR) {
                done = true;
                break;
            }
            if (nlmsg->nlmsg_type != RTM_NEWROUTE) {
                continue;
            }

            struct rtmsg* rtm = (struct rtmsg*)NLMSG_DATA(nlmsg);

            // We only want default routes (dst_len == 0) from the main table.
            if (rtm->rtm_dst_len != 0) {
                continue;
            }
            if (rtm->rtm_table != RT_TABLE_MAIN) {
                continue;
            }

            struct rtattr* rta = RTM_RTA(rtm);
            int rtalen = RTM_PAYLOAD(nlmsg);
            unsigned int oif = 0;
            struct in_addr gw4;
            struct in6_addr gw6;
            bool hasGw4 = false;
            bool hasGw6 = false;
            memset(&gw4, 0, sizeof(gw4));
            memset(&gw6, 0, sizeof(gw6));

            for (; RTA_OK(rta, rtalen); rta = RTA_NEXT(rta, rtalen)) {
                switch (rta->rta_type) {
                case RTA_OIF:
                    oif = *(unsigned int*)RTA_DATA(rta);
                    break;
                case RTA_GATEWAY:
                    if (rtm->rtm_family == AF_INET &&
                        RTA_PAYLOAD(rta) >= sizeof(struct in_addr)) {
                        memcpy(&gw4, RTA_DATA(rta), sizeof(gw4));
                        hasGw4 = true;
                    } else if (rtm->rtm_family == AF_INET6 &&
                               RTA_PAYLOAD(rta) >= sizeof(struct in6_addr)) {
                        memcpy(&gw6, RTA_DATA(rta), sizeof(gw6));
                        hasGw6 = true;
                    }
                    break;
                default:
                    break;
                }
            }

            if (oif == 0) {
                continue;
            }

            // Ignore routes on the VPN tunnel interface.
            unsigned int vpnIndex = if_nametoindex(WG_INTERFACE);
            if (vpnIndex != 0 && oif == vpnIndex) {
                continue;
            }

            char ifname[IF_NAMESIZE] = "unknown";
            if_indextoname(oif, ifname);

            if (hasGw4 && rtm->rtm_family == AF_INET) {
                m_defaultGwIpv4 = gw4;
                m_defaultIfindexIpv4 = oif;
                char gwStr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &gw4, gwStr, sizeof(gwStr));
                logger.debug() << "Found default IPv4 route via"
                               << gwStr << "dev" << ifname;
            } else if (hasGw6 && rtm->rtm_family == AF_INET6) {
                m_defaultGwIpv6 = gw6;
                m_defaultIfindexIpv6 = oif;
                char gwStr[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &gw6, gwStr, sizeof(gwStr));
                logger.debug() << "Found default IPv6 route via"
                               << gwStr << "dev" << ifname;
            }
        }
    }

    close(sock);
}

bool LinuxRouteMonitor::insertRoute(const IPAddress& prefix) {
    logger.debug() << "Adding route to" << prefix.toString();

    const int flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE | NLM_F_ACK;
    return rtmSendRoute(RTM_NEWROUTE, flags, RTN_UNICAST, prefix);
}

bool LinuxRouteMonitor::deleteRoute(const IPAddress& prefix) {
    logger.debug() << "Removing route to" << prefix.toString();

    const int flags = NLM_F_REQUEST | NLM_F_ACK;
    return rtmSendRoute(RTM_DELROUTE, flags, RTN_UNICAST, prefix);
}

// Add an exclusion route for the given prefix, routing it through the
// default gateway on the physical interface instead of the VPN tunnel.
// Adapted from MacosRouteMonitor::addExclusionRoute().
bool LinuxRouteMonitor::addExclusionRoute(const IPAddress& prefix) {
    logger.debug() << "Adding exclusion route for"
                   << prefix.toString();
    if (!m_exclusionRoutes.contains(prefix)) {
        m_exclusionRoutes.append(prefix);
    }

    // If the default route is known, update the routing table immediately.
    if (prefix.address().protocol() == QAbstractSocket::IPv4Protocol &&
        m_defaultIfindexIpv4 != 0) {
        return rtmSendExclusionRoute(RTM_NEWROUTE, prefix,
                                     m_defaultIfindexIpv4, AF_INET,
                                     &m_defaultGwIpv4,
                                     sizeof(m_defaultGwIpv4));
    }
    if (prefix.address().protocol() == QAbstractSocket::IPv6Protocol &&
        m_defaultIfindexIpv6 != 0) {
        return rtmSendExclusionRoute(RTM_NEWROUTE, prefix,
                                     m_defaultIfindexIpv6, AF_INET6,
                                     &m_defaultGwIpv6,
                                     sizeof(m_defaultGwIpv6));
    }

    // Otherwise, the default route isn't known yet. Do nothing and wait
    // for a route change notification to apply it later.
    logger.warning() << "Default gateway not yet known, deferring exclusion"
                        " route for" << prefix.toString();
    return true;
}

bool LinuxRouteMonitor::deleteExclusionRoute(const IPAddress& prefix) {
    logger.debug() << "Removing exclusion route for"
                   << prefix.toString();
    m_exclusionRoutes.removeAll(prefix);

    if (prefix.address().protocol() == QAbstractSocket::IPv4Protocol) {
        return rtmSendExclusionRoute(RTM_DELROUTE, prefix,
                                     m_defaultIfindexIpv4, AF_INET,
                                     &m_defaultGwIpv4,
                                     sizeof(m_defaultGwIpv4));
    }
    if (prefix.address().protocol() == QAbstractSocket::IPv6Protocol) {
        return rtmSendExclusionRoute(RTM_DELROUTE, prefix,
                                     m_defaultIfindexIpv6, AF_INET6,
                                     &m_defaultGwIpv6,
                                     sizeof(m_defaultGwIpv6));
    }
    return false;
}

void LinuxRouteMonitor::flushExclusionRoutes() {
    while (!m_exclusionRoutes.isEmpty()) {
        IPAddress prefix = m_exclusionRoutes.takeFirst();
        logger.debug() << "Flushing exclusion route for" << prefix.toString();
        if (prefix.address().protocol() == QAbstractSocket::IPv4Protocol) {
            rtmSendExclusionRoute(RTM_DELROUTE, prefix,
                                  m_defaultIfindexIpv4, AF_INET,
                                  &m_defaultGwIpv4,
                                  sizeof(m_defaultGwIpv4));
        } else if (prefix.address().protocol() == QAbstractSocket::IPv6Protocol) {
            rtmSendExclusionRoute(RTM_DELROUTE, prefix,
                                  m_defaultIfindexIpv6, AF_INET6,
                                  &m_defaultGwIpv6,
                                  sizeof(m_defaultGwIpv6));
        }
    }
}

// Send a route for VPN tunnel traffic (via amn0 interface).
bool LinuxRouteMonitor::rtmSendRoute(int action, int flags, int type,
                                       const IPAddress& prefix) {
    constexpr size_t rtm_max_size = sizeof(struct rtmsg) +
                                    2 * RTA_SPACE(sizeof(uint32_t)) +
                                    RTA_SPACE(sizeof(struct in6_addr));
    wg_allowedip ip;
    if (!buildAllowedIp(&ip, prefix)) {
        logger.warning() << "Invalid destination prefix";
        return false;
    }

    char buf[NLMSG_SPACE(rtm_max_size)];
    struct nlmsghdr* nlmsg = reinterpret_cast<struct nlmsghdr*>(buf);
    struct rtmsg* rtm = static_cast<struct rtmsg*>(NLMSG_DATA(nlmsg));

    memset(buf, 0, sizeof(buf));
    nlmsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    nlmsg->nlmsg_type = action;
    nlmsg->nlmsg_flags = flags;
    nlmsg->nlmsg_pid = getpid();
    nlmsg->nlmsg_seq = m_nlseq++;
    rtm->rtm_dst_len = ip.cidr;
    rtm->rtm_family = ip.family;
    rtm->rtm_type = type;
    rtm->rtm_table = RT_TABLE_MAIN;
    rtm->rtm_protocol = RTPROT_BOOT;
    rtm->rtm_scope = RT_SCOPE_UNIVERSE;

    if (rtm->rtm_family == AF_INET6) {
        nlmsg_append_attr(nlmsg, sizeof(buf), RTA_DST, &ip.ip6, sizeof(ip.ip6));
    } else {
        nlmsg_append_attr(nlmsg, sizeof(buf), RTA_DST, &ip.ip4, sizeof(ip.ip4));
    }

    int index = if_nametoindex(WG_INTERFACE);
    if (index <= 0) {
        logger.error() << "if_nametoindex() failed:" << strerror(errno);
        return false;
    }
    nlmsg_append_attr32(nlmsg, sizeof(buf), RTA_OIF, index);
    nlmsg_append_attr32(nlmsg, sizeof(buf), RTA_PRIORITY, 1);

    struct sockaddr_nl nladdr;
    memset(&nladdr, 0, sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;
    size_t result = sendto(m_nlsock, buf, nlmsg->nlmsg_len, 0,
                           (struct sockaddr*)&nladdr, sizeof(nladdr));

    return (result == nlmsg->nlmsg_len);
}

// Send an exclusion route through the physical interface's default gateway.
// This pins the route to a specific interface (RTA_OIF) so it bypasses
// the VPN tunnel routes. Adapted from MacosRouteMonitor::rtmSendRoute().
bool LinuxRouteMonitor::rtmSendExclusionRoute(int action,
                                               const IPAddress& prefix,
                                               unsigned int ifindex,
                                               int gwfamily,
                                               const void* gateway,
                                               size_t gwlen) {
    constexpr size_t rtm_max_size = sizeof(struct rtmsg) +
                                    2 * RTA_SPACE(sizeof(struct in6_addr)) +
                                    2 * RTA_SPACE(sizeof(uint32_t));
    wg_allowedip ip;
    if (!buildAllowedIp(&ip, prefix)) {
        logger.warning() << "Invalid destination prefix";
        return false;
    }

    char buf[NLMSG_SPACE(rtm_max_size)];
    struct nlmsghdr* nlmsg = reinterpret_cast<struct nlmsghdr*>(buf);
    struct rtmsg* rtm = static_cast<struct rtmsg*>(NLMSG_DATA(nlmsg));

    memset(buf, 0, sizeof(buf));
    nlmsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    nlmsg->nlmsg_type = action;
    if (action == RTM_NEWROUTE) {
        nlmsg->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE | NLM_F_ACK;
    } else {
        nlmsg->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    }
    nlmsg->nlmsg_pid = getpid();
    nlmsg->nlmsg_seq = m_nlseq++;
    rtm->rtm_dst_len = ip.cidr;
    rtm->rtm_family = ip.family;
    rtm->rtm_type = RTN_UNICAST;
    rtm->rtm_table = RT_TABLE_MAIN;
    rtm->rtm_protocol = RTPROT_STATIC;
    rtm->rtm_scope = RT_SCOPE_UNIVERSE;

    // Append RTA_DST.
    if (rtm->rtm_family == AF_INET6) {
        nlmsg_append_attr(nlmsg, sizeof(buf), RTA_DST, &ip.ip6, sizeof(ip.ip6));
    } else {
        nlmsg_append_attr(nlmsg, sizeof(buf), RTA_DST, &ip.ip4, sizeof(ip.ip4));
    }

    // Append RTA_GATEWAY to route via the physical gateway.
    if (gateway != nullptr && gwlen > 0) {
        nlmsg_append_attr(nlmsg, sizeof(buf), RTA_GATEWAY, gateway, gwlen);
    }

    // Append RTA_OIF to pin the route to the physical interface.
    // This is the critical difference from the previous implementation:
    // without RTA_OIF, the kernel resolves the gateway through the routing
    // table, which after VPN routes are installed may cause the gateway
    // to be resolved through the VPN tunnel.
    if (ifindex > 0) {
        nlmsg_append_attr32(nlmsg, sizeof(buf), RTA_OIF, ifindex);
    }

    // Higher priority than VPN routes.
    nlmsg_append_attr32(nlmsg, sizeof(buf), RTA_PRIORITY, 0);

    struct sockaddr_nl nladdr;
    memset(&nladdr, 0, sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;
    size_t result = sendto(m_nlsock, buf, nlmsg->nlmsg_len, 0,
                           (struct sockaddr*)&nladdr, sizeof(nladdr));

    return (result == nlmsg->nlmsg_len);
}

// Handle a route change notification from the kernel.
// Adapted from MacosRouteMonitor::handleRtmUpdate/handleRtmDelete.
void LinuxRouteMonitor::handleRouteChange(struct nlmsghdr* nlmsg) {
    struct rtmsg* rtm = (struct rtmsg*)NLMSG_DATA(nlmsg);

    // We only care about default routes (dst_len == 0) in the main table.
    if (rtm->rtm_dst_len != 0) {
        return;
    }
    if (rtm->rtm_table != RT_TABLE_MAIN) {
        return;
    }

    struct rtattr* rta = RTM_RTA(rtm);
    int rtalen = RTM_PAYLOAD(nlmsg);
    unsigned int oif = 0;
    struct in_addr gw4;
    struct in6_addr gw6;
    bool hasGw4 = false;
    bool hasGw6 = false;
    memset(&gw4, 0, sizeof(gw4));
    memset(&gw6, 0, sizeof(gw6));

    for (; RTA_OK(rta, rtalen); rta = RTA_NEXT(rta, rtalen)) {
        switch (rta->rta_type) {
        case RTA_OIF:
            oif = *(unsigned int*)RTA_DATA(rta);
            break;
        case RTA_GATEWAY:
            if (rtm->rtm_family == AF_INET &&
                RTA_PAYLOAD(rta) >= sizeof(struct in_addr)) {
                memcpy(&gw4, RTA_DATA(rta), sizeof(gw4));
                hasGw4 = true;
            } else if (rtm->rtm_family == AF_INET6 &&
                       RTA_PAYLOAD(rta) >= sizeof(struct in6_addr)) {
                memcpy(&gw6, RTA_DATA(rta), sizeof(gw6));
                hasGw6 = true;
            }
            break;
        default:
            break;
        }
    }

    // Ignore routes on the VPN tunnel interface.
    unsigned int vpnIndex = if_nametoindex(WG_INTERFACE);
    if (vpnIndex != 0 && oif == vpnIndex) {
        return;
    }

    char ifname[IF_NAMESIZE] = "unknown";
    if (oif != 0) {
        if_indextoname(oif, ifname);
    }

    if (nlmsg->nlmsg_type == RTM_DELROUTE) {
        // Default route was deleted.
        if (rtm->rtm_family == AF_INET) {
            logger.debug() << "Lost default IPv4 route via" << ifname;
            memset(&m_defaultGwIpv4, 0, sizeof(m_defaultGwIpv4));
            m_defaultIfindexIpv4 = 0;
            // Remove exclusion routes that relied on this gateway.
            for (const IPAddress& prefix : m_exclusionRoutes) {
                if (prefix.address().protocol() == QAbstractSocket::IPv4Protocol) {
                    logger.debug() << "Removing exclusion route to"
                                   << prefix.toString();
                    rtmSendExclusionRoute(RTM_DELROUTE, prefix, oif,
                                          AF_INET, nullptr, 0);
                }
            }
        } else if (rtm->rtm_family == AF_INET6) {
            logger.debug() << "Lost default IPv6 route via" << ifname;
            memset(&m_defaultGwIpv6, 0, sizeof(m_defaultGwIpv6));
            m_defaultIfindexIpv6 = 0;
            for (const IPAddress& prefix : m_exclusionRoutes) {
                if (prefix.address().protocol() == QAbstractSocket::IPv6Protocol) {
                    logger.debug() << "Removing exclusion route to"
                                   << prefix.toString();
                    rtmSendExclusionRoute(RTM_DELROUTE, prefix, oif,
                                          AF_INET6, nullptr, 0);
                }
            }
        }
        return;
    }

    // Default route was added or changed — update exclusion routes.
    if (hasGw4 && rtm->rtm_family == AF_INET && oif != 0) {
        char gwStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &gw4, gwStr, sizeof(gwStr));
        logger.debug() << "Updating default IPv4 route via"
                       << gwStr << "dev" << ifname;
        m_defaultGwIpv4 = gw4;
        m_defaultIfindexIpv4 = oif;
        updateExclusionRoutes(AF_INET);
    } else if (hasGw6 && rtm->rtm_family == AF_INET6 && oif != 0) {
        char gwStr[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &gw6, gwStr, sizeof(gwStr));
        logger.debug() << "Updating default IPv6 route via"
                       << gwStr << "dev" << ifname;
        m_defaultGwIpv6 = gw6;
        m_defaultIfindexIpv6 = oif;
        updateExclusionRoutes(AF_INET6);
    }
}

// Reapply all exclusion routes for the given address family using the
// currently known default gateway. Adapted from MacosRouteMonitor's
// exclusion route update loop in handleRtmUpdate().
void LinuxRouteMonitor::updateExclusionRoutes(int family) {
    for (const IPAddress& prefix : m_exclusionRoutes) {
        if (family == AF_INET &&
            prefix.address().protocol() == QAbstractSocket::IPv4Protocol) {
            logger.debug() << "Updating exclusion route to"
                           << prefix.toString();
            rtmSendExclusionRoute(RTM_NEWROUTE, prefix,
                                  m_defaultIfindexIpv4, AF_INET,
                                  &m_defaultGwIpv4,
                                  sizeof(m_defaultGwIpv4));
        } else if (family == AF_INET6 &&
                   prefix.address().protocol() == QAbstractSocket::IPv6Protocol) {
            logger.debug() << "Updating exclusion route to"
                           << prefix.toString();
            rtmSendExclusionRoute(RTM_NEWROUTE, prefix,
                                  m_defaultIfindexIpv6, AF_INET6,
                                  &m_defaultGwIpv6,
                                  sizeof(m_defaultGwIpv6));
        }
    }
}

static void nlmsg_append_attr(struct nlmsghdr* nlmsg, size_t maxlen,
                              int attrtype, const void* attrdata,
                              size_t attrlen) {
    size_t newlen = NLMSG_ALIGN(nlmsg->nlmsg_len) + RTA_SPACE(attrlen);
    if (newlen <= maxlen) {
    char* buf = reinterpret_cast<char*>(nlmsg) + NLMSG_ALIGN(nlmsg->nlmsg_len);
    struct rtattr* attr = reinterpret_cast<struct rtattr*>(buf);
    attr->rta_type = attrtype;
    attr->rta_len = RTA_LENGTH(attrlen);
    memcpy(RTA_DATA(attr), attrdata, attrlen);
    nlmsg->nlmsg_len = newlen;
    }
}

static void nlmsg_append_attr32(struct nlmsghdr* nlmsg, size_t maxlen,
                                int attrtype, uint32_t value) {
    nlmsg_append_attr(nlmsg, maxlen, attrtype, &value, sizeof(value));
}

void LinuxRouteMonitor::nlsockReady() {
    char buf[4096];
    ssize_t len = recv(m_nlsock, buf, sizeof(buf), MSG_DONTWAIT);
    if (len <= 0) {
        return;
    }

    struct nlmsghdr* nlmsg = (struct nlmsghdr*)buf;
    while (NLMSG_OK(nlmsg, len)) {
        if (nlmsg->nlmsg_type == NLMSG_DONE) {
            return;
        }

        // Handle route change notifications (like macOS rtsockReady).
        if (nlmsg->nlmsg_type == RTM_NEWROUTE ||
            nlmsg->nlmsg_type == RTM_DELROUTE) {
            handleRouteChange(nlmsg);
            nlmsg = NLMSG_NEXT(nlmsg, len);
            continue;
        }

        if (nlmsg->nlmsg_type != NLMSG_ERROR) {
            nlmsg = NLMSG_NEXT(nlmsg, len);
            continue;
        }
        struct nlmsgerr* err = static_cast<struct nlmsgerr*>(NLMSG_DATA(nlmsg));
        if (err->error != 0) {
            logger.debug() << "Netlink request failed:" << strerror(-err->error);
        }
        nlmsg = NLMSG_NEXT(nlmsg, len);
    }
}

static bool buildAllowedIp(wg_allowedip* ip,
                                         const IPAddress& prefix) {
    const char* addrString = qPrintable(prefix.address().toString());
    if (prefix.type() == QAbstractSocket::IPv4Protocol) {
    ip->family = AF_INET;
    ip->cidr = prefix.prefixLength();
    return inet_pton(AF_INET, addrString, &ip->ip4) == 1;
    }
    if (prefix.type() == QAbstractSocket::IPv6Protocol) {
    ip->family = AF_INET6;
    ip->cidr = prefix.prefixLength();
    return inet_pton(AF_INET6, addrString, &ip->ip6) == 1;
    }
    return false;
}
