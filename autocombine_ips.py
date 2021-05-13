from pathlib import Path
import re
from sys import argv

with Path(argv[1]).open('r', encoding='utf8') as reader:
    lines = reader.readlines()

fw_lines_part1 = []
fw_lines_part2 = []
fw_lines_part3 = []
ip_lines = []
ip1 = {}
ip2 = {}
ip3 = {}
ip4 = {}
part = 0


def check_ips():
    global ip1, ip2, ip3, ip4
    new_ips = []
    tmp_ips = []
    remove_ips = []
    # ip4
    for _ip4 in ip4.keys():
        tmp_ips.append(_ip4[:_ip4.rindex('.')])
    for tmp_ip in set(tmp_ips):
        if tmp_ips.count(tmp_ip) > 24:
            ip3[tmp_ip] = ip3.get(tmp_ip, 0) + 1
            remove_ips.append(tmp_ip)
            ip3_name = '%s.0/24' % tmp_ip
            new_ips.append(ip3_name)
    # remove
    for _ip4 in list(ip4):
        if _ip4[:_ip4.rindex('.')] in remove_ips or _ip4[:_ip4.rindex('.')] in ip3:
            print("remove %s" % _ip4)
            del ip4[_ip4]
    # reset
    tmp_ips = []
    remove_ips = []

    # ip3
    for _ip3 in ip3.keys():
        tmp_ips.append(_ip3[:_ip3.rindex('.')])
    for tmp_ip in set(tmp_ips):
        if tmp_ips.count(tmp_ip) > 16:
            ip2[tmp_ip] = ip2.get(tmp_ip, 0) + 1
            remove_ips.append(tmp_ip)
            ip2_name = '%s.0.0/16' % tmp_ip
            new_ips.append(ip2_name)
    # remove
    for _ip3 in list(ip3):
        if _ip3[:_ip3.rindex('.')] in remove_ips or _ip3[:_ip3.rindex('.')] in ip2:
            print("remove %s" % _ip3)
            del ip3[_ip3]
    # reset
    tmp_ips = []
    remove_ips = []

    # ip2
    for _ip2 in ip2.keys():
        tmp_ips.append(_ip2[:_ip2.rindex('.')])
    for tmp_ip in set(tmp_ips):
        if tmp_ips.count(tmp_ip) > 8:
            ip1[tmp_ip] = ip1.get(tmp_ip, 0) + 1
            remove_ips.append(tmp_ip)
            ip1_name = '%s.0.0.0/8' % tmp_ip
            new_ips.append(ip1_name)
    # remove
    for _ip2 in list(ip2):
        if _ip2[:_ip2.rindex('.')] in remove_ips or _ip2[:_ip2.rindex('.')] in ip1:
            print("remove %s" % _ip2)
            del ip2[_ip2]

    for _ip in new_ips:
        print('add new rules: %s' % _ip)
    ip1, ip2, ip3, ip4 = dict(sorted(ip1.items())), dict(sorted(ip2.items())), dict(sorted(ip3.items())), dict(sorted(ip4.items()))
    for _ip in ip1:
        fw_lines_part2.append('### tuple ### deny any any 0.0.0.0/0 any %s.0.0.0/8 in\n-A ufw-user-input -s %s.0.0.0/8 -j DROP\n\n' % (_ip, _ip))
        ip_lines.append('%s.0.0.0/8\n' % _ip)
    for _ip in ip2:
        fw_lines_part2.append('### tuple ### deny any any 0.0.0.0/0 any %s.0.0/16 in\n-A ufw-user-input -s %s.0.0/16 -j DROP\n\n' % (_ip, _ip))
        ip_lines.append('%s.0.0/16\n' % _ip)
    for _ip in ip3:
        fw_lines_part2.append('### tuple ### deny any any 0.0.0.0/0 any %s.0/24 in\n-A ufw-user-input -s %s.0/24 -j DROP\n\n' % (_ip, _ip))
        ip_lines.append('%s.0/24\n' % _ip)
    for _ip in ip4:
        fw_lines_part2.append('### tuple ### deny any any 0.0.0.0/0 any %s in\n-A ufw-user-input -s %s -j DROP\n\n' % (_ip, _ip))
        ip_lines.append('%s\n' % _ip)


skip_row_id = 0
for row_id in range(0, len(lines)):
    if row_id < skip_row_id:
        continue
    if part == 0 and '### RULES ###' in lines[row_id]:
        part = 1
    if part == 1 and '### tuple ### allow' in lines[row_id]:
        part = 2

    if part == 0:
        fw_lines_part1.append(lines[row_id])
    elif part == 1:
        if '### tuple ### deny' in lines[row_id]:
            search_line = lines[row_id + 1]
            if '/' in search_line:
                ip = re.compile(r'([0-9]{1,3}[.]){3}[0-9]{1,3}/[1-9]+').search(search_line).group(0)
                [ip, num] = ip.split('/')
                if num == '24':
                    ip = ip[:-2]
                    ip3[ip] = 1
                elif num == '16':
                    ip = ip[:-4]
                    ip2[ip] = 1
                elif num == '8':
                    ip = ip[:-6]
                    ip1[ip] = 1
            else:
                ip = re.compile(r'([0-9]{1,3}[.]){3}[0-9]{1,3}').search(search_line).group(0)
                ip4[ip] = 1
            skip_row_id = row_id + 3
        else:
            fw_lines_part1.append(lines[row_id])
    elif part == 2:
        check_ips()
        fw_lines_part3.append(lines[row_id])
        part = 3
    elif part == 3:
        fw_lines_part3.append(lines[row_id])

with Path(argv[2]).open('w', encoding='utf-8') as fw_writer:
    fw_writer.writelines(fw_lines_part1)
    fw_writer.writelines(fw_lines_part2)
    fw_writer.writelines(fw_lines_part3)
   
