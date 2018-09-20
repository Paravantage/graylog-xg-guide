# Guide for XG Graylog Pipeline

This guide explains the basic steps for creating a simple [Graylog](https://www.graylog.org/) Pipeline to consume logs sent from [Sophos XG](https://www.sophos.com/en-us/products/next-gen-firewall.aspx). It is not meant to be a comprehensive exploration of this topic nor the ultimate authority (or any authority for that matter) on how to accomplish this. What follows is what works for us, your mileage may vary.

## Prerequisites

A Syslog UDP input on Graylog configured as a Syslog Server within XG. Please see the documentation for Graylog and/or XG for help with these configurations.

**Note:** *No extractors were configured on the input used for this guide.*

## General Stream and Pipeline Configuration

Our Graylog server consumes Syslog messages from various sources, including networking appliances and Linux servers. All messages entering our UDP Syslog input are split into streams dedicated to processing pipelines specific to the message source type. We also have a generic Syslog pipeline which is shared by (almost) all of these streams. There are many ways to setup processing flows in Graylog, and this model just seemed to work for us.

In this guide, we will assume you have a similar configuration with all XG messages entering a stream dedicated to XG. If this is not the case, you will most likely want to add a stage at the beginning of the XG Pipeline which filters our any non-XG message from further processing.

## Generic Syslog Pipeline

There are a few rules we like to apply to all syslog messages. Rather than add these rules to every pipeline, we created one pipeline that can be shared by different streams. Several of our rules are specific to our network, but here is an example of what you can (and probably should) do for your XG logs as well as any other Syslog source 

### Stage 0

Since XG is sending Syslog format, go ahead and give yourself the text value of the log level as follows:

    rule "level name"
    when
        true
    then
        set_field("severity",syslog_level($message.level));
    end

## XG Pipeline

This pipeline contains only rules for XG messages. We accomplish the basic message parsing in two separate stages which, in our environment are configured as stage 1 and 2.  As noted above, if you have attached your XG Pipeline to a stream containing non-XG messages, you should include a stage at the beginning of the pipeline to exclude non-XG messages from further processing.

### Stage 1

The first stage of pipeline processing is used to parse the XG log types into distinct message fields. The following rule creates *log_type*, *log_component*, and *log_sub_type* which are used in the next stage for individual message type parsing.


    rule "XG Log Type"
    when
        to_string($message.source) == "xg.lan.paravantage.com"
    then
        set_fields(
            grok(
                pattern: "log_type=%{QUOTEDSTRING:log_type} log_component=%{QUOTEDSTRING:log_component} log_subtype=%{QUOTEDSTRING:log_sub_type}",
                value: to_string($message.message),
                only_named_captures: true
            )
        );
    end

### Stage 2

This stage performs the bulk of extraction work, with rules dedicated to specific log type and sub-types. To implement the optional **Stage 3** you should configure the pipeline to continue as long as one of the rules matches.

#### Firewall Log Type

    rule "XG Firewall Type"
    when
        to_string($message.log_type) == "Firewall"
    then
        set_fields(
            grok(
                pattern: "status=%{QUOTEDSTRING:action}%{SPACE}priority=%{WORD:priority}%{SPACE}duration=%{INT:duration}%{SPACE}fw_rule_id=%{INT:fw_rule_id}%{SPACE}policy_type=%{INT:policy_type}%{SPACE}user_name=%{QUOTEDSTRING:user_name}%{SPACE}user_gp=%{QUOTEDSTRING:user_group}%{SPACE}iap=%{INT:iap}%{SPACE}ips_policy_id=%{INT:ips_policy_id}%{SPACE}appfilter_policy_id=%{INT:app_filter_policy_id}%{SPACE}application=%{QUOTEDSTRING:application}%{SPACE}application_risk=%{INT:application_risk}%{SPACE}application_technology=%{QUOTEDSTRING:application_technology}%{SPACE}application_category=%{QUOTEDSTRING:application_category}%{SPACE}in_interface=%{QUOTEDSTRING:in_interface}%{SPACE}out_interface=%{QUOTEDSTRING:out_interface}%{SPACE}src_mac=%{DATA:src_mac}%{SPACE}src_ip=%{DATA:src_ip}%{SPACE}src_country_code=%{DATA:src_country_code}%{SPACE}dst_ip=%{DATA:dst_ip}%{SPACE}dst_country_code=%{DATA:dst_country_code}%{SPACE}protocol=%{QUOTEDSTRING:protocol}%{SPACE}(src_port=%{INT:src_port}%{SPACE}dst_port=%{INT:dst_port})?(icmp_type=%{INT:icmp_type}%{SPACE}icmp_code=%{INT:icmp_code})?%{SPACE}sent_pkts=%{INT:sent_pkts;int}%{SPACE}recv_pkts=%{INT:recv_pkts;int}%{SPACE}sent_bytes=%{INT:sent_bytes;int}%{SPACE}recv_bytes=%{INT:recv_bytes;int}%{SPACE}tran_src_ip=%{DATA:tran_src_ip}%{SPACE}tran_src_port=%{INT:tran_src_port}%{SPACE}tran_dst_ip=%{DATA:tran_dst_ip}%{SPACE}tran_dst_port=%{INT:tran_dst_port}%{SPACE}srczonetype=%{QUOTEDSTRING:src_zone_type}%{SPACE}srczone=%{QUOTEDSTRING:src_zone}%{SPACE}dstzonetype=%{QUOTEDSTRING:dst_zone_type}%{SPACE}dstzone=%{QUOTEDSTRING:dst_zone}%{SPACE}dir_disp=%{QUOTEDSTRING:dir_disp}%{SPACE}(connevent=%{QUOTEDSTRING:conn_event})?%{SPACE}connid=%{QUOTEDSTRING:conn_id}%{SPACE}vconnid=%{QUOTEDSTRING:v_conn_id}%{SPACE}hb_health=%{QUOTEDSTRING:hb_health}%{SPACE}message=%{QUOTEDSTRING:fw_message}%{SPACE}appresolvedby=%{QUOTEDSTRING:app_resolved_by}%{SPACE}app_is_cloud=%{INT:app_is_cloud;boolean}",
                value: to_string($message.message),
                only_named_captures: true
            )
        );
    end
#### Content Filter Log Type

    rule "XG Content Filter Type"
    when
        to_string($message.log_type) == "Content Filtering"
    then
        set_fields(
            grok(
                pattern: "status=%{QUOTEDSTRING:action}%{SPACE}priority=%{GREEDYDATA:priority}%{SPACE}fw_rule_id=%{INT:fw_rule_id}%{SPACE}user_name=%{QUOTEDSTRING:user_name}%{SPACE}user_gp=%{QUOTEDSTRING:user_group}%{SPACE}iap=%{INT:iap}%{SPACE}category=%{QUOTEDSTRING:category}%{SPACE}category_type=%{QUOTEDSTRING:category_type}%{SPACE}url=%{QUOTEDSTRING:url}%{SPACE}contenttype=%{QUOTEDSTRING:content_type}%{SPACE}override_token=%{QUOTEDSTRING:override_token}%{SPACE}httpresponsecode=%{QUOTEDSTRING:http_response_code}%{SPACE}src_ip=%{IP:src_ip}%{SPACE}dst_ip=%{IP:dst_ip}%{SPACE}protocol=%{QUOTEDSTRING:protocol}%{SPACE}src_port=%{INT:src_port}%{SPACE}dst_port=%{INT:dst_port}%{SPACE}sent_bytes=%{INT:sent_bytes;int}%{SPACE}recv_bytes=%{INT:recv_bytes;int}%{SPACE}domain=%{URIHOST:domain}%{SPACE}exceptions=%{DATA:exceptions}%{SPACE}activityname=%{QUOTEDSTRING:activity_name}%{SPACE}reason=%{QUOTEDSTRING:reason}%{SPACE}user_agent=%{QUOTEDSTRING:user_agent}%{SPACE}status_code=%{QUOTEDSTRING:status_code}%{SPACE}transactionid=%{DATA:transaction_id}%{SPACE}referer=%{QUOTEDSTRING:referer}%{SPACE}download_file_name=%{QUOTEDSTRING:downloaded_file_name}%{SPACE}download_file_type=%{QUOTEDSTRING:downloaded_file_type}%{SPACE}upload_file_name=%{QUOTEDSTRING}%{SPACE}upload_file_type=%{QUOTEDSTRING}%{SPACE}con_id=%{INT:con_id}%{SPACE}application=%{QUOTEDSTRING:application}%{SPACE}app_is_cloud=%{INT:app_is_cloud;boolean}",
                value: to_string($message.message),
                only_named_captures: true
            )
        );
    end

#### IDP Log Type

    rule "XG IDP Type"
    when
        to_string($message.log_type) == "IDP"
    then
        set_fields(
            grok(
                pattern: "priority=%{WORD:priority}%{SPACE}idp_policy_id=%{INT:idp_policy_id}%{SPACE}fw_rule_id=%{INT:fw_rule_id}%{SPACE}user_name=%{QUOTEDSTRING:user_name}%{SPACE}signature_id=%{INT:signature_id}%{SPACE}signature_msg=%{QUOTEDSTRING:signature_msg}%{SPACE}classification=%{QUOTEDSTRING:classification}%{SPACE}rule_priority=%{INT:rule_priority}%{SPACE}src_ip=%{DATA:src_ip}%{SPACE}src_country_code=%{DATA:src_country_code}%{SPACE}dst_ip=%{DATA:dst_ip}%{SPACE}dst_country_code=%{DATA:dst_country_code}%{SPACE}protocol=%{QUOTEDSTRING:protocol}%{SPACE}src_port=%{INT:src_port}%{SPACE}dst_port=%{INT:dst_port}%{SPACE}platform=%{QUOTEDSTRING:platform}%{SPACE}category=%{QUOTEDSTRING:category}%{SPACE}target=%{QUOTEDSTRING:target}",
                value: to_string($message.message),
                only_named_captures: true
            )
        );
    end

#### Authentication Event Log Type

    rule "XG Event Authentication Type"
    when
        (to_string($message.log_type) == "Event") && (to_string($message.log_sub_type) == "Authentication")
    then
        set_fields(
            grok(
                pattern: "status=%{QUOTEDSTRING:status}%{SPACE}priority=%{WORD:priority}%{SPACE}user_name=%{QUOTEDSTRING:user_name}%{SPACE}usergroupname=%{QUOTEDSTRING:user_group}%{SPACE}auth_client=%{QUOTEDSTRING:auth_client}%{SPACE}auth_mechanism=%{QUOTEDSTRING:auth_mechanism}%{SPACE}reason=%{QUOTEDSTRING:reason}%{SPACE}src_ip=%{DATA:src_ip}%{SPACE}message=%{QUOTEDSTRING:auth_message}%{SPACE}name=%{QUOTEDSTRING:name}%{SPACE}src_mac=%{DATA:src_mac}",
                value: to_string($message.message),
                only_named_captures: true
            )
        );
    end

#### System Log Type

    rule "XG System Type"
    when
        to_string($message.log_sub_type) == "System"
    then
        set_fields(
            grok(
                pattern: "(status=%{QUOTEDSTRING:status})?%{SPACE}priority=%{WORD:priority}%{SPACE}(status=%{QUOTEDSTRING:status})?%{GREEDYDATA}message=%{QUOTEDSTRING:system_message}",
                value: to_string($message.message),
                only_named_captures: true
            )
        );
    end

#### SMTP Log Type

    rule "XG SMTP Type"
    when
        to_string($message.log_component) == "SMTP"
    then
        set_fields(
            grok(
                pattern: "priority=%{WORD:priority}%{SPACE}fw_rule_id=%{INT:fw_rule_id}%{SPACE}user_name=%{QUOTEDSTRING:user_name}%{GREEDYDATA}from_email_address=%{QUOTEDSTRING:from_email_address}%{SPACE}to_email_address=%{QUOTEDSTRING:to_email_address}%{SPACE}email_subject=%{QUOTEDSTRING:email_subject}%{GREEDYDATA}src_domainname=%{QUOTEDSTRING:src_domain}",
                value: to_string($message.message),
                only_named_captures: true
            )
        );
    end

#### GUI Event Log Type

    rule "XG GUI Event Type"
    when
        to_string($message.log_type) == "Event" && to_string($message.log_component) == "GUI"
    then
        set_fields(
            grok(
                pattern: "status=%{DATA:QUOTEDSTRING}%{SPACE}priority=%{WORD:priority}%{SPACE}user_name=%{QUOTEDSTRING:user_name}%{SPACE}src_ip=%{DATA:src_ip}%{SPACE}ZONE=%{QUOTEDSTRING:zone}%{SPACE}message=%{QUOTEDSTRING:event_message}",
                value: to_string($message.message),
                only_named_captures: true
            )
        );
    end

### Stage 3

This is optional, and reflects our method of alerting for messages that we somehow missed in our processing rules. The following sets a flag to indicate the XG message was captured and parsed by one of the rules in **Stage 2**.  If any of our XG log entries exit the pipeline without this flag, a notification is sent so we can investigate and update or add rules. We haven't had a anything hit this in a while, but our XG configuration and usage may not match yours, so it is recommended that you perform some form of capture to identify rule deficiencies.

#### Pipeline Processed Flag

    rule "Pipeline Processed Flag"
    when
        true
    then
        set_field("pipeline_processed",true);
    end
