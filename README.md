### 脚本使用说明 
---
注意:
在启动仓库时，需在配置文件中的storage配置中增加delete=true配置项,允许删除镜像,垃圾回收时尽量定期执行,不宜过于频繁 

```bash
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
```
# docker_registry_kit
