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

from zeroconf import IPVersion
from zeroconf.asyncio import AsyncServiceInfo, AsyncZeroconf

# TODO: Remove traceback beautification
from rich.traceback import install
install(show_locals=True)

async def register_services(infos: List[AsyncServiceInfo]) -> None:
    tasks = [aiozc.async_register_service(info) for info in infos]
    background_tasks = await asyncio.gather(*tasks)
    await asyncio.gather(*background_tasks)


async def unregister_services(infos: List[AsyncServiceInfo]) -> None:
    tasks = [aiozc.async_unregister_service(info) for info in infos]
    background_tasks = await asyncio.gather(*tasks)
    await asyncio.gather(*background_tasks)


async def close_aiozc(aiozc: AsyncZeroconf) -> None:
    await aiozc.async_close()


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)

    local_domains = [ d for d in domain_list()['domains'] if d.endswith('.local') ]

    # TODO: Create setting to list interfaces
    wanted_interfaces = [ 'zt3jnskpna' ]
    interfaces = get_network_interfaces()
    ips = []
    for i in wanted_interfaces:
        try:
            ips.append(socket.inet_pton(socket.AF_INET, interfaces[i]['ipv4'].split('/')[0]))
        except:
            pass
        try:
            ips.append(socket.inet_pton(socket.AF_INET6, interfaces[i]['ipv6'].split('/')[0]))
        except:
            pass

    parser = argparse.ArgumentParser()
    parser.add_argument('--debug', action='store_true')
    args = parser.parse_args()

    if args.debug:
        logging.getLogger('zeroconf').setLevel(logging.DEBUG)

    infos = []
    for d in local_domains:
        d_domain=d.replace('.local','')
        infos.append(
            AsyncServiceInfo(
                type_="_device-info._tcp.local.",
                name=d_domain+f"._device-info._tcp.local.",
                addresses=ips,
                port=80,
                server=d+'.',
            )
        )

    print("Registration of .local domains, press Ctrl-C to exit...")
    aiozc = AsyncZeroconf()
    loop = asyncio.get_event_loop()
    loop.run_until_complete(register_services(infos))
    print("Registration complete.")
    try:
        while True:
            time.sleep(0.1)
    except KeyboardInterrupt:
        pass
    finally:
        print("Unregistering...")
        loop.run_until_complete(unregister_services(infos))
        print("Unregistration complete.")
        loop.run_until_complete(close_aiozc(aiozc))

