ansible-api

# -*- coding: utf-8 -*-

#from tempfile import NamedTemporaryFile
import os.path

from ansible.inventory import Inventory
from ansible.runner import Runner
from ansible.playbook import PlayBook
from ansible.inventory.group import Group
from ansible.inventory.host import Host
from ansible import callbacks
from ansible import utils
#from django.template.loader import get_template
#from django.template import Context
from passlib.hash import sha512_crypt

API_DIR = os.path.dirname(os.path.abspath(__file__))
ANSIBLE_DIR = os.path.join(API_DIR, 'playbooks')


class AnsibleError(StandardError):

    def __init__(self, error, data='', message=''):
        super(AnsibleError, self).__init__(message)
        self.error = error
        self.data = data
        self.message = message


class CommandValueError(AnsibleError):

    def __init__(self, field, message=''):
        super(CommandValueError, self).__init__('value:invalid', field, message)


class MyInventory(Inventory):

    def __init__(self, resource):

        self.resource = resource
        self.inventory = Inventory(host_list=[])
        self.gen_inventory()

    def my_add_group(self, hosts, groupname, groupvars=None):

        my_group = Group(name=groupname)

        if groupvars:
            for key, value in groupvars.iteritems():
                my_group.set_variable(key, value)

        for host in hosts:
            hostname = host.get("ip")
            hostip = host.get('ip', hostname)
            hostport = host.get("port")
            username = host.get("username")
            password = host.get("password")
            my_host = Host(name=hostname, port=hostport)
            my_host.set_variable('ansible_ssh_host', hostip)
            my_host.set_variable('ansible_ssh_port', hostport)
            my_host.set_variable('ansible_ssh_user', username)
            my_host.set_variable('ansible_ssh_pass', password)

            for key, value in host.iteritems():
                if key not in ["hostname", "port", "username", "password"]:
                    my_host.set_variable(key, value)

            my_group.add_host(my_host)

        self.inventory.add_group(my_group)

    def gen_inventory(self):

        if isinstance(self.resource, list):
            self.my_add_group(self.resource, 'deploy')
        elif isinstance(self.resource, dict):
            for groupname, hosts_and_vars in self.resource.iteritems():
                self.my_add_group(hosts_and_vars.get("hosts"), groupname, hosts_and_vars.get("vars"))


class MyRunner(MyInventory):

    def __init__(self, *args, **kwargs):
        super(MyRunner, self).__init__(*args, **kwargs)
        self.results_raw = {}

    def run(self, module_name='shell', module_args='', timeout=10, forks=10, pattern='*',
            become=False, become_method='sudo', become_user='root', become_pass=''):

        hoc = Runner(module_name=module_name,
                     module_args=module_args,
                     timeout=timeout,
                     inventory=self.inventory,
                     pattern=pattern,
                     forks=forks,
                     become=become,
                     become_method=become_method,
                     become_user=become_user,
                     become_pass=become_pass
                     )
        self.results_raw = hoc.run()
        logger.debug(self.results_raw)
        return self.results_raw

    @property
    def results(self):
        result = {'failed': {}, 'ok': {}}
        dark = self.results_raw.get('dark')
        contacted = self.results_raw.get('contacted')
        if dark:
            for host, info in dark.items():
                result['failed'][host] = info.get('msg')

        if contacted:
            for host, info in contacted.items():
                if info.get('invocation').get('module_name') in ['raw', 'shell', 'command', 'script']:
                    if info.get('rc') == 0:
                        result['ok'][host] = info.get('stdout') + info.get('stderr')
                    else:
                        result['failed'][host] = info.get('stdout') + info.get('stderr')
                else:
                    if info.get('failed'):
                        result['failed'][host] = info.get('msg')
                    else:
                        result['ok'][host] = info.get('changed')
        return result


class MyTask(MyRunner):

    def __init__(self, *args, **kwargs):
        super(MyTask, self).__init__(*args, **kwargs)

    def passwd_test(self, username, password):


    def chan_root_pw(self, username, password):

        encrypt_pass = sha512_crypt.encrypt(password)
        module_args = 'name=%s password=%s update_password=always' % (username, encrypt_pass)

        self.run("user", module_args, become=True)

        return self.results

    def qd_initialize(self, username, password):


    def qd_php(self, username, password):


    def qd_tomcat(self, username, password):




class CustomAggregateStats(callbacks.AggregateStats):

    def __init__(self):
        super(CustomAggregateStats, self).__init__()
        self.results = []

    def compute(self, runner_results, setup=False, poll=False, ignore_errors=False):
        super(CustomAggregateStats, self).compute(runner_results, setup, poll, ignore_errors)
        self.results.append(runner_results)

    def summarize(self, host):
        summarized_info = super(CustomAggregateStats, self).summarize(host)
        summarized_info['result'] = self.results
        return summarized_info


class MyPlaybook(MyInventory):

    def __init__(self, *args, **kwargs):
        super(MyPlaybook, self).__init__(*args, **kwargs)

    def run(self, playbook_relational_path, extra_vars=None):
        stats = CustomAggregateStats()
        playbook_cb = callbacks.PlaybookCallbacks(verbose=utils.VERBOSITY)
        runner_cb = callbacks.PlaybookRunnerCallbacks(stats, verbose=utils.VERBOSITY)
        playbook_path = os.path.join(ANSIBLE_DIR, playbook_relational_path)

        pb = PlayBook(playbook=playbook_path, stats=stats, callbacks=playbook_cb, runner_callbacks=runner_cb, inventory=self.inventory, extra_vars=extra_vars, check=False)

        self.results_raw = pb.run()

    @property
    def results(self):
        result = {"failed": {}, "ok": {}}

        resultss = self.results_raw.values()[0]
        for i in resultss.get('result'):
            dark = i.get('dark')
            contacted = i.get('contacted')
            if contacted:
                for host, info in contacted.items():
                    if info.get('invocation').get('module_name') in ['raw', 'shell', 'script']:
                        if info.get('rc') == 0:
                            #result['ok'][host] = info.get('stdout') + info.get('stderr')
                            result["ok"][host] = info.get('invocation').get('module_args')
                        else:
                            result["failed"][host] = info.get('invocation').get('module_args')
                            #result['failed'][host] = info.get('stdout') + info.get('stderr')
                    elif info.get('invocation').get('module_name') in ['template', 'copy']:
                        if info.get('changed'):
                            result["ok"][host] = info.get('dest')
                        else:
                            result["failed"][host] = info.get('dest')
                    elif info.get('invocation').get('module_name') in ['command']:
                        if info.get('rc') == 0:
                            result["ok"][host] = info.get('stdout') + info.get('stderr')
                        else:
                            result["failed"][host] = info.get('stdout') + info.get('stderr')
            if dark:
                for host, info in dark.items():
                    result["failed"][host] = info.get('changed')
        return result


class App(MyPlaybook):

    def __init__(self, *args, **kwargs):
        super(App, self).__init__(*args, **kwargs)

    @staticmethod
    def nginx_vars(upstreams, upstream, servers, server_ssls, locations):
        extra_vars = {'upstreams': upstreams, 'upstream': upstream, 'servers': servers, 'server_ssls': server_ssls, 'locations': locations}
        return extra_vars

    def nginx_conf_deploy(self, playbook, upstreams, upstream, servers, server_ssls, locations):
        vars = self.nginx_vars(upstreams, upstream, servers, server_ssls, locations)
        self.run(playbook, vars)
        return self.results
        #return self.results_raw

