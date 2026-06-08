#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib/core';
import { AwsNetworkFirewallPayloadSizeStack } from '../lib/aws-network-firewall-payload-size-stack';

const app = new cdk.App();
new AwsNetworkFirewallPayloadSizeStack(app, 'AwsNetworkFirewallPayloadSizeStack', {
  // アカウントは CLI プロファイル (awsume) 依存。リージョンは東京固定
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: 'ap-northeast-1',
  },
});
