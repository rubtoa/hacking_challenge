from flask import Flask, render_template, request
import subprocess

'''
    a flask app to demo command injection vulnerability
'''

banner = ""
app = Flask(__name__, static_folder='static', template_folder='templates')

@app.route('/')
def index():
    '''
        this is the vulnerable endpoint
    '''
    return render_template('cmd.html')
    #out = subprocess.check_output(cmd, shell=True)

    #return out
@app.route('/execute_command',methods=['POST'])
def execute_command():
    '''
        this is the vulnerable endpoint
    '''
    out = "Bad command - only ping and dig are allowed"
    cmd = request.form['command']
    command_line = f"\nc:> dig {cmd}\n"
    if True:
        try:

            subprocess.call('cd runtime', shell=True)
            out = subprocess.check_output("dig "+str(cmd), shell=True, timeout=5)
        except:
            out = "Timeout reached!\n"
    # convert tabs to spaces
    buff = ''

    for b in out:
        if b == '\t':
            buff += '    '
        else:
            buff += chr(b)


    out = f"{banner}{command_line}{buff}"
    return out



if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=12345)

