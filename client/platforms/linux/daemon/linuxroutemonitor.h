/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef LINUXROUTEMONITOR_H
#define LINUXROUTEMONITOR_H

#include <QByteArray>
#include <QHostAddress>
#include <QList>
#include <QObject>
#include <QSocketNotifier>

#include <netinet/in.h>

#include "ipaddress.h"

struct nlmsghdr;


class LinuxRouteMonitor final : public QObject {
  Q_OBJECT

 public:
  LinuxRouteMonitor(const QString& ifname, QObject* parent = nullptr);
  ~LinuxRouteMonitor();

  bool insertRoute(const IPAddress& prefix);
  bool deleteRoute(const IPAddress& prefix);

  bool addExclusionRoute(const IPAddress& prefix);
  bool deleteExclusionRoute(const IPAddress& prefix);
  void flushExclusionRoutes();

 private:
  bool rtmSendRoute(int action, int flags, int type,
                    const IPAddress& prefix);
  bool rtmSendExclusionRoute(int action, const IPAddress& prefix,
                             unsigned int ifindex, int gwfamily,
                             const void* gateway, size_t gwlen);
  void fetchDefaultRoutes();
  void handleRouteChange(struct nlmsghdr* nlmsg);
  void updateExclusionRoutes(int family);

  QString m_ifname;
  unsigned int m_ifindex = 0;
  int m_nlsock = -1;
  int m_nlseq = 0;
  QSocketNotifier* m_notifier = nullptr;
  QList<IPAddress> m_exclusionRoutes;

  // Default gateway tracking (adapted from MacosRouteMonitor).
  struct in_addr m_defaultGwIpv4;
  unsigned int m_defaultIfindexIpv4 = 0;
  struct in6_addr m_defaultGwIpv6;
  unsigned int m_defaultIfindexIpv6 = 0;

 private slots:
  void nlsockReady();
};

#endif  // LINUXROUTEMONITOR_H
