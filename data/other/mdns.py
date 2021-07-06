#!/usr/bin/env python3

"""
WIP
Pythonic declaration of mDNS .local domains for YunoHost
Based off https://github.com/jstasiak/python-zeroconf/blob/master/tests/test_asyncio.py
"""

import os
import sys
import argparse

import asyncio
import logging
import socket
import time
from typing import List

sys.path.insert(0, "/usr/lib/moulinette/")
from yunohost.domain import domain_list
from yunohost.utils.network import get_network_interfaces
from yunohost.settings import settings_get
from moulinette import m18n
from moulinette.interfaces.cli import get_locale

from zeroconf.asyncio import AsyncServiceInfo, AsyncZeroconf


async def register_services(aiozc: AsyncZeroconf, infos: List[AsyncServiceInfo]) -> None:
    tasks = [aiozc.async_register_service(info) for info in infos]
    background_tasks = await asyncio.gather(*tasks)
    await asyncio.gather(*background_tasks)

async def unregister_services(aiozc: AsyncZeroconf, infos: List[AsyncServiceInfo]) -> None:
    tasks = [aiozc.async_unregister_service(info) for info in infos]
    background_tasks = await asyncio.gather(*tasks)
    await asyncio.gather(*background_tasks)

async def close_aiozc(aiozc: AsyncZeroconf) -> None:
    await aiozc.async_close()


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)

    parser = argparse.ArgumentParser()
    parser.add_argument('--debug', action='store_true')
    args = parser.parse_args()

    if args.debug:
        logging.getLogger('zeroconf').setLevel(logging.DEBUG)


    local_domains = [ d for d in domain_list()['domains'] if d.endswith('.local') ]

    m18n.load_namespace("yunohost")
    m18n.set_locale(get_locale())

    if settings_get('mdns.interfaces'):
        wanted_interfaces = settings_get('mdns.interfaces').split()
    else:
        wanted_interfaces = []
        print('No interface listed for broadcast.')

    aiozcs = []
    interfaces = get_network_interfaces()
    for interface in wanted_interfaces:
        infos = []
        ips = [] # Human-readable IPs
        b_ips = [] # Binary-convered IPs

        # Parse the IPs and prepare their binary version
        try:
            ip = interfaces[interface]['ipv4'].split('/')[0]
            ips.append(ip)
            b_ips.append(socket.inet_pton(socket.AF_INET, ip))
        except:
            pass
        try:
            ip = interfaces[interface]['ipv6'].split('/')[0]
            ips.append(ip)
            b_ips.append(socket.inet_pton(socket.AF_INET6, ip))
        except:
            pass

        # Create a ServiceInfo object for each .local domain
        for d in local_domains:
            d_domain=d.replace('.local','')
            infos.append(
                AsyncServiceInfo(
                    type_="_device-info._tcp.local.",
                    name=d_domain+f"._device-info._tcp.local.",
                    addresses=b_ips,
                    port=80,
                    server=d+'.',
                )
            )
            print('Adding '+d+' with addresses '+str(ips)+' on interface '+interface)

        # Create an AsyncZeroconf object, store it, and start Service registration
        aiozc = AsyncZeroconf(interfaces=ips)
        aiozcs.append(aiozc)
        print("Registration on interface "+interface+"...")
        loop = asyncio.get_event_loop()
        loop.run_until_complete(register_services(aiozc, infos))

    # We are done looping among the interfaces
    print("Registration complete. Press Ctrl-c to exit...")
    try:
        while True:
            time.sleep(0.1)
    except KeyboardInterrupt:
        pass
    finally:
        print("Unregistering...")
        for aiozc in aiozcs:
            loop.run_until_complete(unregister_services(aiozc, infos))
            loop.run_until_complete(close_aiozc(aiozc))
        print("Unregistration complete.")

