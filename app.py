from flask import Flask
from flask import render_template
from flask import request
import fun
import config
import lib

app = Flask(__name__)


@app.route('/')
def nodes_update():  # put application's code here
    return render_template('index.html')


@app.route('/get_url', methods=['POST'])
def get_url():  # put application's code here
    if request.method == 'POST':
        url = request.form['url']
        try:
            re = lib.get_to_data(url)
            print(re)
            return render_template('index.html', url=url, info=re)
        except Exception as error:
            print('error:', error)
            return render_template('index.html', url=url, error=error)
    return render_template('index.html')


@app.route('/nodes_list')
def nodes_list():  # put application's code here
    try:
        nodes = fun.read_nodes(config.NODES_PATH)
        return render_template('node_list.html', nodes_list=nodes)
    except Exception as error:
        return render_template('node_list.html', error=error)


@app.route('/output_list')
def output_list():
    try:
        nodes = fun.read_output(config.OUTPUT_PATH)
        return render_template('node_list.html', nodes_list=nodes)
    except Exception as error:
        return render_template('node_list.html', error=error)


if __name__ == '__main__':
    app.run()
