#!/usr/bin/env python3.6
# docker registry tools
# 在启动仓库时，需在配置文件中的storage配置中增加delete=true配置项，允许删除镜像
"""
Usage: registrykit.py repos --host=<registr_host> --user=<username> --passwd=<password> [--verifyssl  --timeout=<timeout>]
       registrykit.py taglist --host=<registr_host> --imagename=<image_name> --user=<username> --passwd=<password>
       registrykit.py deltag  --host=<registr_host> --imagename=<image_name> --tagname=<tag_name> --user=<username> --passwd=<password>
       registrykit.py garbage_collect  --baseurl=<baseurl> --docker_container_name=<containername> [--timeout=<timeout> --dry_run]
       registrykit.py -h | --help
       registrykit.py --version

Options:
  -h --help
  --dry_run                                dry_run mode
  --verifyssl                              enable sslverify
  --host=<registr_host>                    registry host
  --user=<username>                        registry username
  --passwd=<password>                      registry user password
  --tagname=<tag_name>                     tagname
  --baseurl=<baseurl>                      docker baseurl, example: unix://var/run/docker.sock or tcp://host:port
  --timeout=<timeout>                      timeout [default: 10]
  --imagename=<image_name>                 imagename
  --docker_container_name=<containername>  docker registry container name
"""
import json
import requests
from urllib.parse import urlparse
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import docker
from docopt import docopt
# 禁用安全请求警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class UnknownError(Exception):
    pass


class AuthKeyIncomplete(UnknownError):
    pass


class UserOrPasswordError(UnknownError):
    pass


class HttpSchemaNotFound(UnknownError):
    pass


class NotAllowHttpMethod(UnknownError):
    pass


class ImageTagNotFound(UnknownError):
    pass


class TagListNotFound(UnknownError):
    pass


class RepoListNotFound(UnknownError):
    pass


class NotFoundAuthHeader(UnknownError):
    pass


class IncorrectAuthCode(UnknownError):
    pass


class DockerRegistry(object):

    def __init__(self, host, username, password, verifyssl=True, timeout=10):
        self.host = host
        self.timeout = timeout
        self.username = username
        self.password = password
        self.verifyssl = verifyssl
        if not self.check_http_schema(self.host):
            raise HttpSchemaNotFound
        self.urlparse_result = urlparse(self.host)

    def check_http_schema(self, host):
        if self.host.startswith("http") or self.host.startswith("https"):
            return True
        else:
            return False

    def get_token(self, url, method, body=None):
        if method == "GET":
            first_req = requests.get(
                url, verify=self.verifyssl, timeout=self.timeout)
        elif method == "POST":
            first_req = requests.post(
                url, data=body, verify=self.verifyssl, timeout=self.timeout)
        elif method == "PUT":
            first_req = requests.put(
                url, data=body, verify=self.verifyssl, timeout=self.timeout)
        elif method == "DELETE":
            first_req = requests.delete(
                url, verify=self.verifyssl, timeout=self.timeout)
        elif method == "HEAD":
            first_req = requests.head(
                url, verify=self.verifyssl, timeout=self.timeout)
        else:
            raise NotAllowHttpMethod
        if first_req.status_code == 401:
            www_authenticate = first_req.headers.get("Www-Authenticate")
            if www_authenticate:
                auth_info = self.split_www_authenticate(www_authenticate)
                if "realm" not in auth_info or "service" not in auth_info or "scope" not in auth_info:
                    raise AuthKeyIncomplete
                auth_url = auth_info["realm"] + "?service=" + \
                    auth_info["service"] + "&scope=" + auth_info["scope"]
                auth = HTTPBasicAuth(self.username, self.password)
                auth_req = requests.get(
                    auth_url, auth=auth, verify=self.verifyssl, timeout=self.timeout)
                if auth_req.status_code == 200:
                    return auth_req.json().get("token")
                elif auth_req.status_code == 401:
                    raise UserOrPasswordError
                else:
                    raise auth_req.raise_for_status()
            else:
                raise NotFoundAuthHeader
        else:
            raise IncorrectAuthCode

    def split_www_authenticate(self, www_authenticate):
        auth_string = www_authenticate.split()[1]
        auth_info = {}
        for item in auth_string.split(","):
            auth_key = item.split("=")[0]
            if auth_key == "realm":
                auth_info["realm"] = item.split("=")[1].strip('"')
            elif auth_key == "service":
                auth_info["service"] = item.split("=")[1].strip('"')
            elif auth_key == "scope":
                auth_info["scope"] = item.split("=")[1].strip('"')
            else:
                continue
        return auth_info

    def get_tag_digest(self, imagename, tagname):
        url = self.urlparse_result.scheme + "://" + self.urlparse_result.netloc + \
            "/v2/{}/manifests/{}".format(imagename, tagname)
        access_token = self.get_token(url, "HEAD")
        headers = {'Accept': 'application/vnd.docker.distribution.manifest.v2+json',
                   'Authorization': 'Bearer {}'.format(access_token)}
        digest_req = requests.head(
            url, headers=headers, verify=self.verifyssl, timeout=self.timeout)
        if digest_req.status_code == 200:
            return digest_req.headers.get("Docker-Content-Digest")
        else:
            raise ImageTagNotFound

    def get_tag_list(self, imagename):
        url = self.urlparse_result.scheme + "://" + \
            self.urlparse_result.netloc + "/v2/{}/tags/list".format(imagename)
        access_token = self.get_token(url, "GET")
        headers = {'Authorization': 'Bearer {}'.format(access_token)}
        tag_list_req = requests.get(
            url, headers=headers, verify=self.verifyssl, timeout=self.timeout)
        if tag_list_req.status_code == 200:
            print(json.dumps(tag_list_req.json(), indent=4))
        else:
            raise TagListNotFound

    def get_repository_list(self):
        url = self.urlparse_result.scheme + "://" + \
            self.urlparse_result.netloc + "/v2/_catalog"
        access_token = self.get_token(url, "GET")
        headers = {'Authorization': 'Bearer {}'.format(access_token)}
        repository_list_req = requests.get(
            url, headers=headers, verify=self.verifyssl, timeout=self.timeout)
        if repository_list_req.status_code == 200:
            print(json.dumps(repository_list_req.json(), indent=4))
        else:
            raise RepoListNotFound

    def delete_tag(self, imagename, tagname):
        tag_digest = self.get_tag_digest(imagename, tagname)
        url = self.urlparse_result.scheme + "://" + self.urlparse_result.netloc + \
            "/v2/{}/manifests/{}".format(imagename, tag_digest)
        access_token = self.get_token(url, "DELETE")
        headers = {'Authorization': 'Bearer {}'.format(access_token)}
        tag_delete_req = requests.delete(
            url, headers=headers, verify=self.verifyssl, timeout=self.timeout)
        if tag_delete_req.status_code == 202:
            print("Tag delete sucessfully")
        else:
            tag_delete_req.raise_for_status()

    @staticmethod
    def garbage_collect(base_url, docker_registry_name, version="auto", timeout=10, dry_run=False):
        """
        此操作具有一定危险性,不宜过于频繁操作,且要求清理时不要进行push操作
        """
        docker_ins = docker.DockerClient(
            base_url=base_url, version=version, timeout=timeout)
        docker_registry_container = docker_ins.containers.get(
            docker_registry_name)
        if dry_run:
            docker_registry_container_gc_result = docker_registry_container.exec_run(
                "registry garbage-collect /etc/docker/registry/config.yml -d")
        else:
            docker_registry_container_gc_result = docker_registry_container.exec_run(
                "registry garbage-collect /etc/docker/registry/config.yml")
            docker_registry_container.restart()

        if docker_registry_container_gc_result[0] == 0:
            print("garbage collect sucessfully")
        else:
            print("garbage collect failed")
        print("\nResult:\n{}".format(str(docker_registry_container_gc_result[1], encoding="utf-8")))


def main():
    arguments = docopt(__doc__, version='0.1.0')
    if arguments.get("repos"):
        docker_registry_ins = DockerRegistry(
            host=arguments.get("--host"), username=arguments.get("--user"), password=arguments.get("--passwd"), verifyssl=arguments.get("--verifyssl"), timeout=int(arguments.get("--timeout")))
        docker_registry_ins.get_repository_list()
    elif arguments.get("taglist"):
        docker_registry_ins = DockerRegistry(
            host=arguments.get("--host"), username=arguments.get("--user"), password=arguments.get("--passwd"), verifyssl=arguments.get("--verifyssl"), timeout=int(arguments.get("--timeout")))
        docker_registry_ins.get_tag_list(arguments.get("--imagename"))
    elif arguments.get("deltag"):
        docker_registry_ins = DockerRegistry(
            host=arguments.get("--host"), username=arguments.get("--user"), password=arguments.get("--passwd"), verifyssl=arguments.get("--verifyssl"), timeout=int(arguments.get("--timeout")))
        docker_registry_ins.delete_tag(arguments.get("--imagename"), arguments.get("--tagname"))
    elif arguments.get("garbage_collect"):
        DockerRegistry.garbage_collect(base_url=arguments.get("--baseurl"), docker_registry_name=arguments.get("--docker_container_name"), timeout=int(arguments.get("--timeout")), dry_run=arguments.get("--dry_run"))


if __name__ == '__main__':
    main()
