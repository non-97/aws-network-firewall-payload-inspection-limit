import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as nfw from 'aws-cdk-lib/aws-networkfirewall';

/**
 * AWS Network Firewall の「検査可能なペイロードサイズ(ストリームリアセンブリ深度)」を
 * 実測するための検証環境。
 *
 * 構成 (案A 単一VPC内 East-West):
 *   VPC 10.0.0.0/16 (単一AZ)
 *     - Firewall Subnet 10.0.0.0/24 : NFW エンドポイント専用
 *     - Client   Subnet 10.0.1.0/24 : Client EC2 (curl 実行側)
 *     - Server   Subnet 10.0.2.0/24 : Server EC2 (HTTP サーバ / マーカーファイル配信)
 *
 * Client <-> Server の通信を more specific route で NFW エンドポイント経由に強制し、
 * Suricata ルールでペイロード内の文字列を検出する。
 * Client/Server サブネットは Public とし、SSM 管理はインターネット (IGW) 経由。
 * East-West の検査トラフィックは more specific route で NFW を通るため管理経路と分離される。
 */
export class AwsNetworkFirewallPayloadSizeStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const vpcCidr = '10.0.0.0/16';
    const clientCidr = '10.0.1.0/24';
    const serverCidr = '10.0.2.0/24';

    // マーカー文字列。レスポンスボディ末尾に埋め込み、検出可否で深度を測る
    const canary = 'PAYLOADCANARY';
    const blockWord = 'BLOCKME';

    // ---------------------------------------------------------------------
    // 1. VPC と 3 サブネット
    //    Client/Server は Public (SSM をインターネット経由で使う)。
    //    Firewall は NFW エンドポイント専用 (インターネット不要なので Isolated)。
    //    各サブネットが専用ルートテーブルを持つ。
    // ---------------------------------------------------------------------
    const vpc = new ec2.Vpc(this, 'Vpc', {
      ipAddresses: ec2.IpAddresses.cidr(vpcCidr),
      maxAzs: 1,
      natGateways: 0,
      subnetConfiguration: [
        { name: 'firewall', subnetType: ec2.SubnetType.PRIVATE_ISOLATED, cidrMask: 24 },
        { name: 'client', subnetType: ec2.SubnetType.PUBLIC, cidrMask: 24 },
        { name: 'server', subnetType: ec2.SubnetType.PUBLIC, cidrMask: 24 },
      ],
    });

    const firewallSubnet = vpc.selectSubnets({ subnetGroupName: 'firewall' }).subnets[0];
    const clientSubnet = vpc.selectSubnets({ subnetGroupName: 'client' }).subnets[0];
    const serverSubnet = vpc.selectSubnets({ subnetGroupName: 'server' }).subnets[0];

    // ---------------------------------------------------------------------
    // 2. EC2 (Client / Server) — Amazon Linux 2023, SSM 管理, キーペアなし
    // ---------------------------------------------------------------------
    const ec2Role = new iam.Role(this, 'Ec2Role', {
      assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonSSMManagedInstanceCore'),
      ],
    });

    const instanceSg = new ec2.SecurityGroup(this, 'InstanceSg', {
      vpc,
      description: 'Lab EC2 SG: allow ICMP and HTTP(8080) within VPC',
      allowAllOutbound: true,
    });
    // 検証トラフィック (ping / curl) を VPC 内で許可
    instanceSg.addIngressRule(ec2.Peer.ipv4(vpcCidr), ec2.Port.allIcmp(), 'ICMP within VPC');
    instanceSg.addIngressRule(ec2.Peer.ipv4(vpcCidr), ec2.Port.tcp(8080), 'HTTP test within VPC');

    const machineImage = ec2.MachineImage.latestAmazonLinux2023({
      cpuType: ec2.AmazonLinuxCpuType.X86_64,
    });
    const instanceType = ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO);

    // --- Server EC2: マーカーファイル生成 + HTTP サーバ起動 ---
    const serverUserData = ec2.UserData.forLinux();
    serverUserData.addCommands(
      [
        'set -xe',
        'dnf install -y python3',
        'mkdir -p /opt/payload/www',
        // マーカー埋め込みファイル生成スクリプト (末尾にマーカーを配置)
        "cat > /opt/payload/gen.sh <<'GENEOF'",
        '#!/bin/bash',
        '# usage: gen.sh <total_bytes>  指定サイズのファイル末尾にマーカーを埋め込む',
        'set -e',
        'N=$1',
        `MARKER="${canary}"`,
        'F=/opt/payload/www/payload_${N}.bin',
        'LEN=${#MARKER}',
        'head -c $((N - LEN)) /dev/zero | tr "\\0" "A" > "$F"',
        'printf "%s" "$MARKER" >> "$F"',
        'echo "generated $F size=$(stat -c %s "$F") marker_at_tail"',
        'GENEOF',
        'chmod +x /opt/payload/gen.sh',
        // デフォルトのサイズセットを生成 (16KB 〜 4MiB)
        'for N in 16384 32768 65536 131072 262144 524288 1048576 1572864 2097152 3145728 4194304; do /opt/payload/gen.sh $N; done',
        // 制御用ファイル: マーカー先頭(必ず検出) / 遮断ワード
        `printf '${canary} baseline at head' > /opt/payload/www/baseline.txt`,
        `printf 'this payload contains ${blockWord} keyword' > /opt/payload/www/blockme.txt`,
        // HTTP サーバを systemd で常駐化
        "cat > /etc/systemd/system/payload-http.service <<'SVCEOF'",
        '[Unit]',
        'Description=Payload test HTTP server',
        'After=network.target',
        '[Service]',
        'WorkingDirectory=/opt/payload/www',
        'ExecStart=/usr/bin/python3 -m http.server 8080',
        'Restart=always',
        '[Install]',
        'WantedBy=multi-user.target',
        'SVCEOF',
        'systemctl daemon-reload',
        'systemctl enable --now payload-http.service',
      ].join('\n'),
    );

    const serverInstance = new ec2.Instance(this, 'ServerInstance', {
      vpc,
      vpcSubnets: { subnets: [serverSubnet] },
      instanceType,
      machineImage,
      role: ec2Role,
      securityGroup: instanceSg,
      userData: serverUserData,
    });

    // --- Client EC2: テストスクリプト配置 (Server の private IP を埋め込み) ---
    const clientUserData = ec2.UserData.forLinux();
    clientUserData.addCommands(
      [
        'set -xe',
        "cat > /opt/run-test.sh <<'TESTEOF'",
        '#!/bin/bash',
        '# usage: run-test.sh [server_ip]  各サイズを curl し HTTP/ダウンロードサイズを表示',
        'set -e',
        `SERVER="\${1:-${serverInstance.instancePrivateIp}}"`,
        'echo "target server: $SERVER"',
        'for N in 16384 32768 65536 131072 262144 524288 1048576 1572864 2097152 3145728 4194304; do',
        '  CODE=$(curl -s -o /dev/null -w "%{http_code} size=%{size_download}" "http://$SERVER:8080/payload_${N}.bin" || echo "ERR")',
        '  printf "N=%s\\t%s\\n" "$N" "$CODE"',
        '  sleep 3',
        'done',
        'TESTEOF',
        'chmod +x /opt/run-test.sh',
      ].join('\n'),
    );

    const clientInstance = new ec2.Instance(this, 'ClientInstance', {
      vpc,
      vpcSubnets: { subnets: [clientSubnet] },
      instanceType,
      machineImage,
      role: ec2Role,
      securityGroup: instanceSg,
      userData: clientUserData,
    });
    // Server の private IP を参照するため依存を明示
    clientInstance.node.addDependency(serverInstance);

    // ---------------------------------------------------------------------
    // 3. Network Firewall (ステートフル Suricata ルール)
    // ---------------------------------------------------------------------
    // 検証ルール:
    //   sid 1000001: マーカー検出 (alert, 生 content/tcp) — 実測では深度に縛られず深部でも発火
    //   sid 1000002: 遮断ワード検出 (drop) — 通過/遮断テスト
    //   sid 1000003: リアセンブリ深度到達の検出 (alert) — 深度超過の根拠ログ (診断用)
    //   sid 1000004: マーカー検出 (alert, http.response_body) — HTTP層の検査深度に縛られる想定。
    //                マーカーが深度より深い位置にあるとマッチしない = ドキュメントの
    //                「rule intermittently not matching」を再現するための比較ルール。
    const suricataRules = [
      `alert tcp any any -> any any (msg:"CANARY-DETECTED"; flow:established; content:"${canary}"; sid:1000001; rev:1;)`,
      `drop tcp any any -> any any (msg:"BLOCKME-DROPPED"; flow:established; content:"${blockWord}"; sid:1000002; rev:1;)`,
      `alert tcp any any -> any any (msg:"REASSEMBLY-DEPTH-REACHED"; flow:established; stream-event:reassembly_depth_reached; sid:1000003; rev:1;)`,
      `alert http any any -> any any (msg:"CANARY-HTTP-BODY"; flow:established,to_client; http.response_body; content:"${canary}"; sid:1000004; rev:1;)`,
    ].join('\n');

    const ruleGroup = new nfw.CfnRuleGroup(this, 'StatefulRuleGroup', {
      ruleGroupName: 'payload-canary-rules',
      type: 'STATEFUL',
      capacity: 100,
      ruleGroup: {
        rulesSource: { rulesString: suricataRules },
        statefulRuleOptions: { ruleOrder: 'DEFAULT_ACTION_ORDER' },
      },
    });

    const firewallPolicy = new nfw.CfnFirewallPolicy(this, 'FirewallPolicy', {
      firewallPolicyName: 'payload-inspection-policy',
      firewallPolicy: {
        // ステートレスはすべてステートフルエンジンへ転送
        statelessDefaultActions: ['aws:forward_to_sfe'],
        statelessFragmentDefaultActions: ['aws:forward_to_sfe'],
        statefulRuleGroupReferences: [{ resourceArn: ruleGroup.attrRuleGroupArn }],
      },
    });

    const firewall = new nfw.CfnFirewall(this, 'Firewall', {
      firewallName: 'payload-inspection-fw',
      firewallPolicyArn: firewallPolicy.attrFirewallPolicyArn,
      vpcId: vpc.vpcId,
      subnetMappings: [{ subnetId: firewallSubnet.subnetId }],
    });

    // ロギング: ALERT (ルールヒット) と FLOW (フロー記録) を CloudWatch Logs へ
    const alertLogGroup = new logs.LogGroup(this, 'AlertLogGroup', {
      logGroupName: '/nfw/payload-lab/alert',
      retention: logs.RetentionDays.ONE_WEEK,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });
    const flowLogGroup = new logs.LogGroup(this, 'FlowLogGroup', {
      logGroupName: '/nfw/payload-lab/flow',
      retention: logs.RetentionDays.ONE_WEEK,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    new nfw.CfnLoggingConfiguration(this, 'LoggingConfiguration', {
      firewallArn: firewall.attrFirewallArn,
      loggingConfiguration: {
        logDestinationConfigs: [
          {
            logType: 'ALERT',
            logDestinationType: 'CloudWatchLogs',
            logDestination: { logGroup: alertLogGroup.logGroupName },
          },
          {
            logType: 'FLOW',
            logDestinationType: 'CloudWatchLogs',
            logDestination: { logGroup: flowLogGroup.logGroupName },
          },
        ],
      },
    });

    // ---------------------------------------------------------------------
    // 4. more specific route — Client <-> Server を NFW エンドポイント経由に強制
    //    attrEndpointIds は ["<az>:<vpce-id>"] 形式。: で split して vpce-id を抽出
    // ---------------------------------------------------------------------
    const firewallEndpointId = cdk.Fn.select(
      1,
      cdk.Fn.split(':', cdk.Fn.select(0, firewall.attrEndpointIds)),
    );

    // Client サブネット -> Server CIDR は FW エンドポイントへ (local /16 より詳細で優先)
    new ec2.CfnRoute(this, 'ClientToServerViaFirewall', {
      routeTableId: clientSubnet.routeTable.routeTableId,
      destinationCidrBlock: serverCidr,
      vpcEndpointId: firewallEndpointId,
    });
    // Server サブネット -> Client CIDR は FW エンドポイントへ (対称ルーティング)
    new ec2.CfnRoute(this, 'ServerToClientViaFirewall', {
      routeTableId: serverSubnet.routeTable.routeTableId,
      destinationCidrBlock: clientCidr,
      vpcEndpointId: firewallEndpointId,
    });

    // ---------------------------------------------------------------------
    // 5. 出力
    // ---------------------------------------------------------------------
    new cdk.CfnOutput(this, 'ClientInstanceId', { value: clientInstance.instanceId });
    new cdk.CfnOutput(this, 'ServerInstanceId', { value: serverInstance.instanceId });
    new cdk.CfnOutput(this, 'ServerPrivateIp', { value: serverInstance.instancePrivateIp });
    new cdk.CfnOutput(this, 'AlertLogGroupName', { value: alertLogGroup.logGroupName });
    new cdk.CfnOutput(this, 'FlowLogGroupName', { value: flowLogGroup.logGroupName });
    new cdk.CfnOutput(this, 'StartTestCommand', {
      value: `aws ssm start-session --target ${clientInstance.instanceId}`,
    });
  }
}
