import base64
import threading
from scapy.all import sniff
import json
import parse_proto as pp
import time
import os
import re


def package_handle(data):
    sniff_datas.append(bytes(data))


def xor(b_data, b_key):
    decrypt_data = b""
    for j in range(len(b_data)):
        decrypt_data += (b_data[j] ^ b_key[j % len(b_key)]).to_bytes(1, byteorder="big", signed=False)
    return decrypt_data


def remove_magic(b_data):
    try:
        cut1 = b_data[6]
        cut2 = b_data[5]
        b_data = b_data[8 + 2:]
        b_data = b_data[:len(b_data) - 2]
        b_data = b_data[cut2:]
        return b_data[cut1:]
    except IndexError as e:
        print("IndexError in remove_magic: %s" % e)


def get_packet_id(b_data):
    packet_id = int.from_bytes(b_data[2:4], byteorder="big", signed=False)
    return packet_id


def get_proto_name_by_id(i_id):
    try:
        proto_name = d_pkt_id[str(i_id)]
        return proto_name
    except KeyError as e:
        print("KeyError in get_proto_name_by_id: %s" % e)
        return False


def sniff_(iface_):
    sniff(iface=iface_, count=0, filter="udp port 22102||22101", prn=package_handle)


def find_key():
    i = 0
    head = ""
    have_got_id_key = False
    have_got_data_key = False
    d_windseed = {}
    encrypted_windseed = b""
    while True:
        if i <= len(sniff_datas) - 1:
            b_data = sniff_datas[i]
            b_data = b_data[42:]
            i += 1
            if have_got_data_key and have_got_id_key:
                frg = b_data[9]
                sn = int.from_bytes(b_data[16:20], byteorder="little", signed=False)
                if frg + sn == first_frg + first_sn:
                    if frg not in d_windseed:
                        d_windseed[frg] = b_data[28:]
                    else:
                        continue
                    frgs = list(d_windseed.keys())
                    if frgs[0] + 1 == len(frgs):
                        sorted_frgs = sorted(d_windseed.items(), key=lambda x: x[0], reverse=True)
                        t_data = list(zip(*sorted_frgs))[1]
                        for frg_data in t_data:
                            encrypted_windseed += frg_data
                        get_seed = False
                        offset = len(encrypted_windseed) - len(windseed_text)
                        full_key = xor(encrypted_windseed[offset:], windseed_text)
                        keys = [full_key[i: i + 4096] for i in range(4096 - offset, len(full_key), 4096)]
                        decrypted_key = max(set(keys), key=keys.count)
                        if keys.count(decrypted_key) > 1:
                            get_seed = True
                            print("get key")
                        if get_seed:
                            pkg_parser = threading.Thread(target=parse, args=(decrypted_key,))
                            kcp_dealing = threading.Thread(target=handle_kcp, args=(id_key,))
                            pkg_parser.start()
                            kcp_dealing.start()
                            break
                        else:
                            print("请重试")
                            exit()
            else:
                if not head:
                    if len(b_data) > 20:
                        head = b_data[:2]
                    else:
                        continue
                if len(b_data) > 20:
                    if not have_got_id_key:
                        b_data = b_data[28:]
                        if b_data.startswith(b"$\x8f") or b_data.startswith(head):
                            continue
                        else:
                            id_key = xor(b_data[:4], b"Eg\x00\x9c")
                            if id_key:
                                have_got_id_key = True
                    else:
                        packet_id = xor(b_data[28:32], id_key)
                        if packet_id == b"\x45\x67\x04\x85":
                            first_frg = b_data[9]
                            first_sn = int.from_bytes(b_data[16:20], byteorder="little", signed=False)
                            have_got_data_key = True
                            d_windseed[first_frg] = b_data[28:]


def parse(decrypt_key):
    i = 0
    weapon_file = open("my_weapon.json", "w", encoding="utf-8")
    reliquary_file = open("my_reliquary.json", "w", encoding="utf-8")
    reliquary_list = []
    weapon_list = []
    while True:
        if i <= len(packet) - 1:
            get = False
            try:
                if i >= 50:
                    get = lock.acquire()
                    for j in range(50):
                        packet.pop(0)
                    i -= 50
            finally:
                if get:
                    lock.release()
            b_data = packet[i]
            i += 1
            b_data = xor(b_data, decrypt_key)
            packet_id = get_packet_id(b_data)
            proto_name = get_proto_name_by_id(packet_id)
            b_data = remove_magic(b_data)
            if proto_name:
                if packet_id == 679:
                    store = pp.parse(b_data, str(packet_id))
                    for item in store["item_list"]:
                        if "equip" in item:
                            equip = item["equip"]
                            item_id = item['item_id']
                            if "weapon" in equip:
                                weapon_name = weapon_name_dict[str(item_id)]
                                weapon = equip["weapon"]
                                if not 'affix_map' in weapon:  # 一星武器直接跳
                                    continue
                                level = weapon["level"]
                                affix = weapon['affix_map'][0]
                                for key, value in affix.items():
                                    refinement = value + 1
                                weapon_list.append({"name": weapon_name, "level": level, "refinement": refinement})
                            elif "reliquary" in equip:
                                reliquary_name = reliquary_name_dict[str(item_id)]
                                reliquary = equip["reliquary"]
                                level = reliquary["level"]
                                main_prop = reliquary['main_prop_id']
                                主属性 = main_prop_dict[str(main_prop)]
                                副属性 = {}
                                sub_prop_list = reliquary['append_prop_id_list']
                                for prop in sub_prop_list:
                                    sub_prop = sub_prop_dict[str(prop)]
                                    for key, value in sub_prop.items():
                                        if value.endswith("%"):
                                            value = percent_convert_decimal(value)
                                        else:
                                            value = int(value)
                                        if key in 副属性:
                                            副属性[key] += value
                                        else:
                                            副属性[key] = value
                                for prop_name, prop_value in 副属性.items():
                                    if prop_value < 1:
                                        副属性[prop_name] = "%.1f%%" % (prop_value * 100)
                                    else:
                                        副属性[prop_name] = "%d" % prop_value
                                reliquary_list.append(
                                    {"name": reliquary_name, "level": level, "main_prop": 主属性, "sub_prop": 副属性})
                    json.dump(weapon_list, weapon_file, ensure_ascii=False, indent=1)
                    json.dump(reliquary_list, reliquary_file, ensure_ascii=False, indent=1)
                    print("导出完成")
                    break


def handle_kcp(id_key):
    i = 6
    found = False
    while True:
        if i <= len(sniff_datas) - 1:
            get = False
            try:
                if i >= 100:
                    get = lock.acquire()
                    for j in range(100):
                        sniff_datas.pop(0)
                    i -= 100
            finally:
                if get:
                    lock.release()
            data = sniff_datas[i]
            i += 1
            data = data[42:]
            skip = False
            while len(data) != 0:
                length = int.from_bytes(data[24:28], byteorder="little", signed=False)
                if length == 0:
                    data = data[28:]
                    continue
                else:
                    head = xor(data[28:32], id_key)
                    frg = data[9]
                    sn = int.from_bytes(data[16:20], byteorder="little", signed=False)
                    if head.startswith(b"\x45\x67") and frg == 0:
                        skip = True
                    else:
                        skip = False
                        if head.startswith(b"\x45\x67"):
                            packt_id = get_packet_id(head)
                            if packt_id == 679:
                                if sn + frg not in handled_kcp_packet:
                                    if sn + frg not in kcp:
                                        kcp[sn + frg] = {frg: data[28: 28 + length]}
                                else:
                                    skip = True
                            else:
                                skip = True
                        else:
                            if sn + frg in kcp:
                                if frg in kcp[sn + frg]:
                                    skip = True
                                else:
                                    kcp[sn + frg][frg] = data[28: 28 + length]
                    offset = length + 28
                    data = data[offset:]
            if not skip:
                for key1, value1 in kcp.items():
                    frgs = list(value1.keys())
                    if len(frgs) == frgs[0] + 1:
                        sorted_dict = sorted(value1.items(), key=lambda x: x[0], reverse=True)
                        t_data = list(zip(*sorted_dict))[1]
                        b_data = b""
                        for frg_data in t_data:
                            b_data += frg_data
                        packet.append(b_data)
                        handled_kcp_packet.append(key1)
                        found = True
                        del kcp[key1]
                        break
            if found:
                break


def read_windseed():
    f = open("plaintext.bin", "rb")
    b_windseed = f.read()
    f.close()
    return b_windseed


def read_json(file):
    with open(file, "r", encoding="utf-8") as f:
        text = json.load(f)
    return text


def percent_convert_decimal(percent_number: str) -> float:
    number = percent_number[:-1]
    integer_, decimal_ = number.split(".")
    return round(float(number)/100, len(decimal_) + 2)


config = read_json("./nahida_config.json")
windseed_text = read_windseed()
union_cmd = read_json("./ucn_id.json")
d_pkt_id = read_json("./packet_id.json")
main_prop_dict = read_json("./main_prop.json")
sub_prop_dict = read_json("./sub_prop.json")
reliquary_name_dict = read_json("./reliquary.json")
weapon_name_dict = read_json("./weapon.json")
sniff_datas = []
packet = []
handled_without_kcp_packet = []
handled_kcp_packet = []
kcp = {}
dev = config["device_name"]
if dev == "NPF_{}":
    with os.popen("getmac", "r") as c:
        text = c.read()
    iface = re.findall("(?<=_{).*?(?=})", text)[0]
    dev = "NPF_{%s}" % iface
    with open("config.json", "w", encoding="utf-8") as f:
        config["device_name"] = dev
        json.dump(config, f)
lock = threading.Lock()
now_time = time.strftime("%Y%m%d%H%M%S")
sniffer = threading.Thread(target=sniff_, args=(dev,))
key_finder = threading.Thread(target=find_key)
sniffer.start()
key_finder.start()
