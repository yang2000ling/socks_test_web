import lib
import node_lib


def read_nodes(nodes_path):
    buff = lib.read_nodes(nodes_path)
    nodes_list = []
    for n in buff:
        node = node_lib.node_decoder(n)
        nodes_list.append(node)
    return nodes_list


def read_output(output_path):
    buff = open(output_path, 'r', encoding='utf-8').read()
    uri_list = node_lib.decode_base64(buff).strip().split('\n')
    output_list = []
    for i in uri_list:
        output_list.append(node_lib.node_decoder(i))
    return output_list


if __name__ == '__main__':
    a = read_output('e:\\output.txt')
    for n in a:
        print(n)
