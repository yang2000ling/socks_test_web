import node_lib
import requests
import yaml
import config

NODES_TXT_PATH = config.NODES_PATH


def read_nodes(nodes_path):
    """读取节点数据，返回节点列表"""
    f = open(nodes_path, 'r', encoding='utf-8')
    buff = f.read().strip().split('\n')
    return buff


def nodes_deduplication(nodes_list, nodes_path=NODES_TXT_PATH):
    """uri格式节点去重"""
    f_nodes = open(nodes_path, 'r', encoding='utf-8')
    data_list = f_nodes.read().strip().split('\n')
    data_list_len = len(data_list)
    for i in nodes_list:
        if i[:5] == 'ss://':
            if node_lib.check_ss(data_list, i) == 0:
                print('nodes_list append {}'.format(i))
                data_list.append(i)
        elif i[:8] == 'vmess://':
            print(i)
            if node_lib.check_vmess(data_list, i) == 0:
                print('nodes_list append {}'.format(i))
                data_list.append(i)
        elif i[:9] == 'trojan://':
            if node_lib.check_trojan(data_list, i) == 0:
                print('nodes_list append {}'.format(i))
                data_list.append(i)
    f_nodes.close()
    f_nodes_w = open(NODES_TXT_PATH, 'w+', encoding='utf-8')
    for i in data_list:
        if len(i) >= 10:
            f_nodes_w.write(i + '\n')
    return [data_list_len, len(data_list), len(data_list) - data_list_len]


def sub_to_data(sub_buff):
    """读取订阅内容sub_text，节点去重后写入nodes.txt"""
    nodes_list = node_lib.subscribe_to_list(sub_buff)
    return nodes_deduplication(nodes_list)


def clash_to_data(yml_buff):
    """读取clash配置内容提取节点，写入nodes.txt"""
    nodes_list = []
    buff = yaml.load(yml_buff, Loader=yaml.SafeLoader)
    nodes = buff['proxies']
    for i in nodes:
        if i['type'] == 'ss':
            nodes_list.append(node_lib.ss_encode(i))
        elif i['type'] == 'vmess':
            nodes_list.append(node_lib.vmess_encode(i, flag='base64'))
        elif i['type'] == 'trojan':
            nodes_list.append(node_lib.trojan_encode(i))
    return nodes_deduplication(nodes_list)


def sub_file_to_data(sub_file):
    """读取订阅文件sub_text，节点去重后写入nodes.txt"""
    f = open(sub_file)
    sub_text = f.read()
    sub_to_data(sub_text)


def clash_file_to_data(clash_yml):
    """读取clash配置文件提取节点"""
    fs = open(clash_yml, encoding='utf-8')
    clash_to_data(fs)


def get_to_data(url):
    """读取在线内容（支持订阅和clash），写入nodes.txt"""
    buff = requests.get(url).content
    try:
        yaml_buff = yaml.load(buff.decode('utf-8'), Loader=yaml.SafeLoader)
        return clash_to_data(buff)
    except:
        try:
            return sub_to_data(buff.decode('utf-8'))
        except Exception as error:
            raise error


if __name__ == '__main__':
    yml_url = 'https://raw.githubusercontent.com/pojiezhiyuanjun/freev2/master/1017clash.yml'
    sub_url = 'https://raw.githubusercontent.com/pojiezhiyuanjun/freev2/master/1017.txt'
    get_to_data(yml_url)
