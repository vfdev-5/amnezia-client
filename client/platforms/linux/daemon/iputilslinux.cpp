/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "iputilslinux.h"

#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <QString>
#include <QScopeGuard>

#include "daemon/wireguardutils.h"
#include "leakdetector.h"
#include "logger.h"

namespace {
Logger logger("IPUtilsLinux");
}

IPUtilsLinux::IPUtilsLinux(QObject* parent) : IPUtils(parent) {
  MZ_COUNT_CTOR(IPUtilsLinux);
  logger.debug() << "IPUtilsLinux created.";
}

IPUtilsLinux::~IPUtilsLinux() {
  MZ_COUNT_DTOR(IPUtilsLinux);
  logger.debug() << "IPUtilsLinux destroyed.";
}

bool IPUtilsLinux::addInterfaceIPs(const InterfaceConfig& config) {
  bool ret = addIP4AddressToDevice(config);
  addIP6AddressToDevice(config);
  return ret;
}

bool IPUtilsLinux::setMTUAndUp(const InterfaceConfig& config) {
  // Create socket file descriptor to perform the ioctl operations on
  int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
  if (sockfd < 0) {
    logger.error() << "Failed to create ioctl socket.";
    return false;
  }
  auto guard = qScopeGuard([&] { close(sockfd); });

  // Setup the interface to interact with
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, WG_INTERFACE, IFNAMSIZ);

  // MTU
  // FIXME: We need to know how many layers deep this particular
  // interface is into a tunnel to work effectively. Otherwise
  // we will run into fragmentation issues.
  ifr.ifr_mtu = config.m_deviceMTU;
  int ret = ioctl(sockfd, SIOCSIFMTU, &ifr);
  if (ret) {
    logger.error() << "Failed to set MTU -- " << config.m_deviceMTU << " -- Return code: " << ret;
    return false;
  }

  // Get the current interface flags first
  strncpy(ifr.ifr_name, WG_INTERFACE, IFNAMSIZ);
  ret = ioctl(sockfd, SIOCGIFFLAGS, &ifr);
  if (ret) {
    logger.error() << "Failed to get interface flags:" << strerror(errno);
    return false;
  }

  // Up
  ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);
  ret = ioctl(sockfd, SIOCSIFFLAGS, &ifr);
  if (ret) {
    logger.error() << "Failed to set device up -- Return code: " << ret;
    return false;
  }

  return true;
}

bool IPUtilsLinux::addIP4AddressToDevice(const InterfaceConfig& config) {
  struct ifreq ifr;
  struct sockaddr_in* ifrAddr = (struct sockaddr_in*)&ifr.ifr_addr;

  // Name the interface and set family
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, WG_INTERFACE, IFNAMSIZ);
  ifr.ifr_addr.sa_family = AF_INET;

  // Extract the host IP address (before '/') and prefix length.
  // Note: QHostAddress::parseSubnet() returns the network address, not the
  // host address. E.g. "10.8.0.4/24" would yield "10.8.0.0". We need the
  // actual host IP, so we split the string manually.
  QString addrStr = config.m_deviceIpv4Address;
  int prefixLength = 32;
  int slashPos = addrStr.indexOf('/');
  if (slashPos > 0) {
    bool ok = false;
    int parsed = addrStr.mid(slashPos + 1).toInt(&ok);
    if (ok && parsed >= 0 && parsed <= 32) {
      prefixLength = parsed;
    } else {
      logger.warning() << "Invalid IPv4 prefix length in"
                       << config.m_deviceIpv4Address << ", defaulting to /32";
    }
    addrStr = addrStr.left(slashPos);
  }
  QByteArray _deviceAddr = addrStr.toLocal8Bit();
  char* deviceAddr = _deviceAddr.data();
  inet_pton(AF_INET, deviceAddr, &ifrAddr->sin_addr);

  // Create IPv4 socket to perform the ioctl operations on
  int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
  if (sockfd < 0) {
    logger.error() << "Failed to create ioctl socket.";
    return false;
  }
  auto guard = qScopeGuard([&] { close(sockfd); });

  // Set the interface address
  int ret = ioctl(sockfd, SIOCSIFADDR, &ifr);
  if (ret) {
    logger.error() << "Failed to set IPv4: " << deviceAddr
                   << "error:" << strerror(errno);
    return false;
  }

  // Set the subnet mask
  struct sockaddr_in* ifrMask = (struct sockaddr_in*)&ifr.ifr_netmask;
  memset(ifrMask, 0, sizeof(*ifrMask));
  ifrMask->sin_family = AF_INET;
  if (prefixLength == 0) {
    ifrMask->sin_addr.s_addr = 0;
  } else {
    ifrMask->sin_addr.s_addr = htonl(0xFFFFFFFF << (32 - prefixLength));
  }
  ret = ioctl(sockfd, SIOCSIFNETMASK, &ifr);
  if (ret) {
    logger.error() << "Failed to set IPv4 netmask, error:" << strerror(errno);
    return false;
  }

  return true;
}

bool IPUtilsLinux::addIP6AddressToDevice(const InterfaceConfig& config) {
  // Set up the ifr and the companion ifr6
  struct in6_ifreq ifr6;
  memset(&ifr6, 0, sizeof(ifr6));
  ifr6.prefixlen = 64;

  // Extract the host IPv6 address (before '/').
  // Note: QHostAddress::parseSubnet() returns the network address, not the
  // host address. We need the actual host IP, so we split the string manually.
  QString addrStr = config.m_deviceIpv6Address;
  int slashPos = addrStr.indexOf('/');
  if (slashPos > 0) {
    bool ok = false;
    uint parsed = addrStr.mid(slashPos + 1).toUInt(&ok);
    if (ok && parsed <= 128) {
      ifr6.prefixlen = parsed;
    } else {
      logger.warning() << "Invalid IPv6 prefix length in"
                       << config.m_deviceIpv6Address << ", defaulting to /64";
    }
    addrStr = addrStr.left(slashPos);
  }
  QByteArray _deviceAddr = addrStr.toLocal8Bit();
  char* deviceAddr = _deviceAddr.data();
  inet_pton(AF_INET6, deviceAddr, &ifr6.addr);

  // Create IPv6 socket to perform the ioctl operations on
  int sockfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_IP);
  if (sockfd < 0) {
    logger.error() << "Failed to create ioctl socket.";
    return false;
  }
  auto guard = qScopeGuard([&] { close(sockfd); });

  // Get the index of named ifr and link with ifr6
  struct ifreq ifr;
  strncpy(ifr.ifr_name, WG_INTERFACE, IFNAMSIZ);
  ifr.ifr_addr.sa_family = AF_INET6;
  int ret = ioctl(sockfd, SIOGIFINDEX, &ifr);
  if (ret) {
    logger.error() << "Failed to get ifindex. Return code: " << ret;
    return false;
  }
  ifr6.ifindex = ifr.ifr_ifindex;

  // Set ifr6 to the interface
  ret = ioctl(sockfd, SIOCSIFADDR, &ifr6);
  if (ret && (errno != EEXIST)) {
    logger.error() << "Failed to set IPv6: " << deviceAddr
                   << "error:" << strerror(errno);
    return false;
  }

  return true;
}
