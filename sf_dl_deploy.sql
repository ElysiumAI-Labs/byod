USE ROLE SYSADMIN;

CREATE WAREHOUSE IF NOT EXISTS EA_SECURITY_DATALAKE_WH WITH WAREHOUSE_SIZE='X-SMALL';

CREATE DATABASE IF NOT EXISTS EA_SECURITY_DATALAKE; 

USE DATABASE EA_SECURITY_DATALAKE;

CREATE SCHEMA IF NOT EXISTS RAW;

CREATE SCHEMA IF NOT EXISTS ANALYTICS;

USE SCHEMA RAW;

CREATE STAGE IF NOT EXISTS AMZ_AWS_STAGE
  STORAGE_INTEGRATION = AMZ_AWS_SF
  URL = 's3://cf-demo-test/'
  file_format=(
            TYPE = "CSV",
            COMPRESSION = "AUTO",
            FIELD_DELIMITER = " ",
            SKIP_BYTE_ORDER_MARK = TRUE
        );
  
        
CREATE TABLE IF NOT EXISTS AMZ_AWS_CLOUDTRAIL(
  GUID VARCHAR(16777216),
  COMMIT_TIME TIMESTAMP_NTZ(9),
  ORIGINAL_STRING VARIANT,
  SERVICE VARCHAR(200),
  DATA_FILE_NAME VARCHAR(16777216)
);


CREATE TABLE IF NOT EXISTS AMZ_AWS_GUARDDUTY (
  GUID VARCHAR(16777216),
  COMMIT_TIME TIMESTAMP_NTZ(9),
  ORIGINAL_STRING VARIANT,
  SERVICE VARCHAR(200),
  DATA_FILE_NAME VARCHAR(16777216)
);


CREATE TABLE IF NOT EXISTS AMZ_AWS_VPC (
  GUID VARCHAR(16777216),
  COMMIT_TIME TIMESTAMP_NTZ(9),
  ORIGINAL_STRING VARIANT,
  SERVICE VARCHAR(200),
  DATA_FILE_NAME VARCHAR(16777216)
);


CREATE OR REPLACE FILE FORMAT CSV_SPACE_FORMAT
    TYPE = csv
    field_delimiter = ' ';


CREATE OR REPLACE FILE FORMAT CSV_TAB_FORMAT
    TYPE = csv
    field_delimiter = "\t";




CREATE OR REPLACE pipe AMZ_AWS_CLOUDTRAIL_PIPE auto_ingest=true as 
COPY INTO AMZ_AWS_CLOUDTRAIL(GUID, COMMIT_TIME, service, ORIGINAL_STRING, DATA_FILE_NAME) FROM 
(select uuid_string(), to_timestamp_ntz(CONVERT_TIMEZONE('UTC', current_timestamp)) as COMMIT_TIME, split_part(metadata$filename,'/',1) as service, 
parse_json(regexp_substr(to_variant($1),'.*Z (\{.*\})',1,1,'e',1)) as ORIGINAL_STRING, metadata$filename as DATA_FILE_NAME 
from '@amz_aws_stage/cloudtrail' (file_format=>CSV_TAB_FORMAT, pattern=>'.*.gz'));



create or replace pipe AMZ_AWS_GUARDDUTY_PIPE auto_ingest=true as 
COPY INTO AMZ_AWS_GUARDDUTY(GUID, COMMIT_TIME, service, ORIGINAL_STRING, DATA_FILE_NAME) FROM 
(select uuid_string(), to_timestamp_ntz(CONVERT_TIMEZONE('UTC', current_timestamp)) as COMMIT_TIME, split_part(metadata$filename,'/',1) as service, 
parse_json(regexp_substr(to_variant($1),'.*Z (\{.*\})',1,1,'e',1)) as ORIGINAL_STRING, metadata$filename as DATA_FILE_NAME 
from '@amz_aws_stage/guardduty' (file_format=>CSV_TAB_FORMAT, pattern=>'.*.gz'));



create or replace pipe AMZ_AWS_VPC_PIPE auto_ingest=true as 
COPY INTO AMZ_AWS_VPC(GUID, COMMIT_TIME, service, ORIGINAL_STRING, DATA_FILE_NAME) FROM 
(select uuid_string(), to_timestamp_ntz(CONVERT_TIMEZONE('UTC', current_timestamp)) as COMMIT_TIME, split_part(metadata$filename,'/',1) as service,
to_variant(object_construct(
      'event_time', $1,
      'account_id', $2,
      'action', $3,
      'az_id', $4,
      'bytes', $5,
      'dstaddr', $6,
      'dstport', $7,
      'end_Time', $8,
      'flow_direction', $9,
      'instance_id', $10,
      'interface_id', $11,
      'log_status', $12,
      'packets', $13,
      'pkt_dst_aws_service', $14,
      'pkt_dstaddr', $15,
      'pkt_src_aws_service', $16,
      'pkt_srcaddr', $17,
      'protocol', $18,
      'region', $19,
      'srcaddr', $20,
      'srcport', $21,
      'start_Time', $22,
      'sublocation_id', $23,
      'sublocation_type', $24,
      'subnet_id', $25,
      'tcp_flags', $26,
      'traffic_path', $27,
      'type', $28,
      'version', $29,
      'vpc_id', $30
    )) as ORIGINAL_STRING, 
metadata$filename as DATA_FILE_NAME 
from '@amz_aws_stage/VPC' (file_format=>CSV_SPACE_FORMAT, pattern=>'.*.gz'));



ALTER PIPE AMZ_AWS_CLOUDTRAIL_PIPE REFRESH;


ALTER PIPE AMZ_AWS_GUARDDUTY_PIPE REFRESH;


ALTER PIPE AMZ_AWS_VPC_PIPE REFRESH;



USE SCHEMA ANALYTICS;

CREATE OR REPLACE VIEW AMZ_AWS_VPC_FLOW_ODM AS
SELECT
original_string,
guid,
commit_time,
original_string:event_time as event_time,
original_string:account_id as account_id,
original_string:action as action,
original_string:az_id as az_id,
original_string:bytes as bytes,
original_string:dstaddr as dstaddr,
original_string:dstport as dstport,
parse_json(original_string:end_Time)::int::timestamp_ntz(9) AS END_TIME,
original_string:flow_direction as flow_direction,
original_string:instance_id as instance_id,
original_string:interface_id as interface_id,
original_string:log_status as log_status,
original_string:packets as packets,
original_string:pkt_dst_aws_service as pkt_dst_aws_service,
original_string:pkt_dstaddr as pkt_dstaddr,
original_string:pkt_src_aws_service as pkt_src_aws_service,
original_string:pkt_srcaddr as pkt_srcaddr,
original_string:protocol as protocol,
original_string:region as region,
original_string:srcaddr as srcaddr,
original_string:srcport as srcport,
parse_json(original_string:start_Time)::int::timestamp_ntz(9) AS START_TIME,
original_string:sublocation_id as sublocation_id,
original_string:sublocation_type as sublocation_type,
original_string:subnet_id as subnet_id,
original_string:tcp_flags as tcp_flags,
original_string:traffic_path as traffic_path,
original_string:type as type,
original_string:version as version,
original_string:vpc_id as vpc_id,
CASE WHEN TRY_TO_NUMERIC(SPLIT_PART(original_string:dstaddr, '.', 1)) = 10
OR original_string:dstaddr like any ('192.168.%','169.254.%','fe80%','fc%','fd%','::ffff:10.%','::ffff:192.168.%','::ffff:169.254.%')
OR (SPLIT_PART(original_string:dstaddr, '.', 1) = 172 and TRY_TO_NUMERIC(SPLIT_PART(original_string:dstaddr, '.', 2)) between 16 and 31)
OR (original_string:dstaddr LIKE '::ffff:172.%' and TRY_TO_NUMERIC(SPLIT_PART(original_string:dstaddr, '.', 2)) between 16 and 31)
THEN 'LOCAL' ELSE 'REMOTE' END AS DSTPORT_TYPE
from EA_SECURITY_DATALAKE.RAW.AMZ_AWS_VPC;





CREATE OR REPLACE VIEW AMZ_AWS_S3_ODM AS
SELECT
ORIGINAL_STRING,
GUID,
COMMIT_TIME,
ORIGINAL_STRING:account::VARCHAR                                    AS  ACCOUNT_ID,
ORIGINAL_STRING:detail:userIdentity:arn::VARCHAR                            AS  SRC_USER_ARN ,
ORIGINAL_STRING:detail:userIdentity:accountId::VARCHAR                          AS  SRC_USER_ID ,
ORIGINAL_STRING:detail:userIdentity::VARIANT                              AS  SRC_USER_INFO  ,
--ORIGINAL_STRING:detail:userIdentity:userName::VARCHAR                         AS  SRC_USER_NAME  ,
ORIGINAL_STRING:detail:userIdentity:sessionContext:sessionIssuer:arn::VARCHAR             AS  SRC_USER_SESSION_CONTEXT_ISSUER_ACCOUNT_ARN ,
ORIGINAL_STRING:detail:userIdentity:sessionContext:sessionIssuer:accountId::VARCHAR           AS  SRC_USER_SESSION_CONTEXT_ISSUER_ACCOUNT_ID ,
--ORIGINAL_STRING:detail:userIdentity:sessionContext:sessionIssuer::VARIANT               AS  SRC_USER_SESSION_CONTEXT_ISSUER_INFO,
ORIGINAL_STRING:detail:userIdentity:sessionContext:sessionIssuer:principalId::VARCHAR         AS  SRC_USER_SESSION_CONTEXT_ISSUER_PRINCIPAL_ID ,
ORIGINAL_STRING:detail:userIdentity:sessionContext:sessionIssuer:type::VARCHAR              AS  SRC_USER_SESSION_CONTEXT_ISSUER_TYPE ,
ORIGINAL_STRING:detail:userIdentity:sessionContext:sessionIssuer:userName::VARCHAR            AS  SRC_USER_SESSION_CONTEXT_ISSUER_USER_NAME ,
--ORIGINAL_STRING:detail:userIdentity:sessionContext::VARIANT                       AS  SRC_USER_SESSION_INFO  ,
--ORIGINAL_STRING:detail:userIdentity:sessionIssuer::VARIANT                        AS  SRC_USER_SESSION_ISSUER_INFO ,
ORIGINAL_STRING:detail:userIdentity:principalId::VARCHAR                        AS  SRC_USER_SID ,
ORIGINAL_STRING:detail:userIdentity:type::VARCHAR                           AS  SRC_USER_TYPE    ,
ORIGINAL_STRING:detail:userIdentity:sessionContext:attributes:mfaAuthenticated::BOOLEAN             AS  MFA_SESSION_FLAG ,
ORIGINAL_STRING:detail:userIdentity:sessionContext:attributes:creationDate::TIMESTAMP               AS  NEW_USER_SESSION_TIME ,
ORIGINAL_STRING:detail:managementEvent::BOOLEAN                             AS  ADMIN_FLAG,
ORIGINAL_STRING:"detail-type"::VARCHAR                                  AS  AWS_DETAIL_TYPE,
ORIGINAL_STRING:detail:eventVersion::VARCHAR                              AS  AWS_EVENT_VERSION,
ORIGINAL_STRING:detail::VARIANT                                     AS  DETAIL_INFO,
ORIGINAL_STRING:source::VARCHAR                                     AS  DST_SERVICE_NAME    ,
ORIGINAL_STRING:detail:recipientAccountId::VARCHAR                            AS  DST_USER_ID  ,
'AWS'                                                   AS  DVC_PRODUCT,
'Amazon'                                                AS  DVC_VENDOR,
'*'                                                   AS  DVC_VERSION,
ORIGINAL_STRING:detail:errorCode::VARCHAR                               AS  ERROR_CODE  ,
ORIGINAL_STRING:detail:errorMessage::VARCHAR                              AS  ERROR_DESC   ,
ORIGINAL_STRING:detail:eventCategory::VARCHAR                             AS  EVENT_CAT_NAME  ,
ORIGINAL_STRING:detail:eventID::VARCHAR                                 AS  EVENT_GUID   ,
ORIGINAL_STRING:detail:eventName::VARCHAR                               AS  EVENT_NAME ,
ORIGINAL_STRING:detail:eventSource::VARCHAR                               AS  EVENT_SERVICE_NAME,
ORIGINAL_STRING:time::TIMESTAMP                                     AS  EVENT_TIME  ,
ORIGINAL_STRING:detail:eventType::VARCHAR                               AS  EVENT_TYPE   ,
ORIGINAL_STRING:detail:requestID::VARCHAR                               AS  REQUEST_GUID  ,
ORIGINAL_STRING:detail:requestParameters::VARIANT                           AS  REQUEST_INFO  ,
ORIGINAL_STRING:detail:responseElements::VARIANT                            AS  RESPONSE_INFO  ,
ORIGINAL_STRING:detail:readOnly::BOOLEAN                                AS  READONLY_FLAG  ,
ORIGINAL_STRING:region::VARCHAR                                     AS  REGION_NAME,
ORIGINAL_STRING:detail:userIdentity:invokedBy::VARCHAR                          AS  SRC_SERVICE_NAME ,
original_string:"detail-type"::VARCHAR                                          AS  SRC_TYPE,
ORIGINAL_STRING:detail:userAgent::VARCHAR                               AS  USERAGENT,
ORIGINAL_STRING:detail:additionalEventData::VARIANT                           AS  ADDN_EVENT_INFO  ,
ORIGINAL_STRING:detail:additionalEventData:bytesTransferredIn::NUMBER                                   AS  BYTES_TRNSF_IN,
ORIGINAL_STRING:detail:additionalEventData:bytesTransferredOut::NUMBER                                  AS  BYTES_TRNSF_OUT,
ORIGINAL_STRING:detail:additionalEventData:AuthenticationMethod::VARCHAR AS AUTHENTICATION_METHOD,
ORIGINAL_STRING:detail:additionalEventData:CipherSuite::VARCHAR AS CIPHER_SUITE,
ORIGINAL_STRING:detail:additionalEventData:SSEApplied::VARCHAR AS SSE_APPLIED,
ORIGINAL_STRING:detail:additionalEventData:SignatureVersion::VARCHAR AS SIGNATURE_VERSION,
ORIGINAL_STRING:detail:requestParameters:Host::VARCHAR AS REQUEST_PARAMS_HOST,
ORIGINAL_STRING:detail:requestParameters:bucketName::VARCHAR AS REQUEST_BUCKET_NAME,
ORIGINAL_STRING:detail:responseElements:"x-amz-server-side-encryption"::VARCHAR AS ENCRYPTION_SERVER_SIDE
from EA_SECURITY_DATALAKE.RAW.AMZ_AWS_CLOUDTRAIL
where original_string:source = 'aws.s3';





CREATE OR REPLACE VIEW AMZ_AWS_EC2_ODM AS
SELECT
  'AWS'                                       AS  DVC_PRODUCT,
  'Amazon'                                    AS  DVC_VENDOR,
  '*'                                                   AS  DVC_VERSION,
  COMMIT_TIME,
  GUID,
  ORIGINAL_STRING,
  'Amazon EC2 - AWS API Call via CloudTrail'                                                    AS  SRC_TYPE,
  ORIGINAL_STRING:detail:eventID::VARCHAR                                 AS  EVENT_GUID,
  ORIGINAL_STRING:account::VARCHAR                                    AS  ACCOUNT_ID,
  ORIGINAL_STRING:region::VARCHAR                                     AS  REGION_NAME,
  ORIGINAL_STRING:source::VARCHAR                                     AS  DST_SERVICE_NAME,
  ORIGINAL_STRING:time::TIMESTAMP                                     AS  EVENT_TIME,
  ORIGINAL_STRING:"detail-type"::VARCHAR                                  AS  AWS_DETAIL_TYPE,
  ORIGINAL_STRING:detail:eventSource::VARCHAR                                   AS  EVENT_SERVICE_NAME,
  ORIGINAL_STRING:resources::VARIANT                                                          AS  RESOURCE_LIST    ,
  ORIGINAL_STRING:detail:managementEvent::BOOLEAN                             AS  ADMIN_FLAG,
  ORIGINAL_STRING:detail:userIdentity:arn::VARCHAR                            AS  SRC_USER_ARN ,
  ORIGINAL_STRING:detail:userIdentity:accountId::VARCHAR                          AS  SRC_USER_ID ,
  ORIGINAL_STRING:detail:userIdentity::VARIANT                              AS  SRC_USER_INFO  ,
  ORIGINAL_STRING:detail:userIdentity:userName::VARCHAR                         AS  SRC_USER_NAME  ,
  ORIGINAL_STRING:detail:sharedEventID::VARCHAR                             AS  SHARED_EVENT_GUID,
  ORIGINAL_STRING:detail:userIdentity:sessionContext:sessionIssuer:arn::VARCHAR             AS  SRC_USER_SESSION_CONTEXT_ISSUER_ACCOUNT_ARN ,
  ORIGINAL_STRING:detail:userIdentity:sessionContext:sessionIssuer:accountId::VARCHAR           AS  SRC_USER_SESSION_CONTEXT_ISSUER_ACCOUNT_ID ,
  ORIGINAL_STRING:detail:userIdentity:sessionContext:sessionIssuer::VARIANT               AS  SRC_USER_SESSION_CONTEXT_ISSUER_INFO,
  ORIGINAL_STRING:detail:userIdentity:sessionContext:sessionIssuer:principalId::VARCHAR         AS  SRC_USER_SESSION_CONTEXT_ISSUER_PRINCIPAL_ID ,
  ORIGINAL_STRING:detail:userIdentity:sessionContext:sessionIssuer:type::VARCHAR              AS  SRC_USER_SESSION_CONTEXT_ISSUER_TYPE ,
  ORIGINAL_STRING:detail:userIdentity:sessionContext:sessionIssuer:userName::VARCHAR            AS  SRC_USER_SESSION_CONTEXT_ISSUER_USER_NAME ,
  ORIGINAL_STRING:detail:userIdentity:sessionContext::VARIANT                       AS  SRC_USER_SESSION_INFO  ,
  ORIGINAL_STRING:detail:userIdentity:sessionIssuer::VARIANT                        AS  SRC_USER_SESSION_ISSUER_INFO ,
  ORIGINAL_STRING:detail:userIdentity:principalId::VARCHAR                        AS  SRC_USER_SID ,
  ORIGINAL_STRING:detail:userIdentity:type::VARCHAR                           AS  SRC_USER_TYPE    ,
  ORIGINAL_STRING:detail:sourceIPAddress::VARCHAR                             AS  SRC_IP ,
  ORIGINAL_STRING:detail:eventCategory::VARCHAR                             AS  EVENT_CAT_NAME  ,
  ORIGINAL_STRING:detail:requestID::VARCHAR                               AS  REQUEST_GUID  ,
  ORIGINAL_STRING:detail:responseElements::VARIANT                            AS  RESPONSE_INFO  ,
  ORIGINAL_STRING:detail:errorMessage::VARCHAR                              AS  ERROR_DESC   ,
  ORIGINAL_STRING:detail:readOnly::BOOLEAN                                AS  READONLY_FLAG  ,
  ORIGINAL_STRING:detail:requestParameters::VARIANT                           AS  REQUEST_INFO  ,
  ORIGINAL_STRING:detail:eventType::VARCHAR                               AS  EVENT_TYPE   ,
  ORIGINAL_STRING:detail:recipientAccountId::VARCHAR                            AS  DST_USER_ID  ,
  ORIGINAL_STRING:detail:errorCode::VARCHAR                               AS  ERROR_CODE  ,
  ORIGINAL_STRING:detail:serviceEventDetails::VARIANT                           AS  SERVICE_EVENT_DETAILS,
  ORIGINAL_STRING:detail:userAgent::VARCHAR                               AS  USERAGENT,
  ORIGINAL_STRING:detail:eventName::VARCHAR                               AS  EVENT_NAME ,
  ORIGINAL_STRING:detail:eventVersion::VARCHAR                              AS  AWS_EVENT_VERSION,
  ORIGINAL_STRING:detail:requestParameters:instancesSet:items[0]:instanceId::varchar as INSTANCE_ID,
  ORIGINAL_STRING:detail:requestParameters:networkInterfaceId::varchar  as NETWORK_INTER_ID
from EA_SECURITY_DATALAKE.RAW.AMZ_AWS_CLOUDTRAIL
where original_string:source = 'aws.ec2';



CREATE OR REPLACE VIEW AMZ_AWS_IAM_ODM AS
SELECT ORIGINAL_STRING,
GUID,
COMMIT_TIME,
ORIGINAL_STRING:account::VARCHAR                                    AS  ACCOUNT_ID,
ORIGINAL_STRING:detail:addendum::VARIANT                                AS  ADDENDUM_INFO,
ORIGINAL_STRING:detail:addendum:originalRequestID::VARCHAR                        AS  ADDENDUM_ORIGINAL_REQUEST_GUID,
ORIGINAL_STRING:detail:addendum:originalEventID::VARCHAR                        AS  ADDENDUM_ORIGINAL_EVENT_GUID,
ORIGINAL_STRING:detail:addendum:reason::VARCHAR                             AS  ADDENDUM_REASON,
ORIGINAL_STRING:detail:addendum:updatedFields::VARIANT                          AS  ADDENDUM_UPDATED_FIELDS,
ORIGINAL_STRING:detail:additionalEventData:LoginTo::VARCHAR                       AS  ADDITIONAL_HOST,
ORIGINAL_STRING:detail:additionalEventData::VARIANT                           AS  ADDITIONAL_INFO,
ORIGINAL_STRING:detail:additionalEventData:MfaType::VARCHAR                       AS  ADDTIONAL_MFA_TYPE,
ORIGINAL_STRING:detail:additionalEventData:MFAUsed::VARCHAR                       AS  ADDITIONAL_MFA_FLAG,
ORIGINAL_STRING:detail:additionalEventData:MobileVersion::VARCHAR                   AS  ADDITIONAL_MOBILE_FLAG,
ORIGINAL_STRING:detail:managementEvent::BOOLEAN                             AS  ADMIN_FLAG,
ORIGINAL_STRING:detail:apiVersion::VARCHAR                                AS  AWS_API_VERSION,
ORIGINAL_STRING:"detail-type"::VARCHAR                                  AS  AWS_DETAIL_TYPE,
ORIGINAL_STRING:detail:eventVersion::VARCHAR                              AS  AWS_EVENT_VERSION,
ORIGINAL_STRING:detail:sessionCredentialFromConsole::BOOLEAN                      AS  CONSOLE_SESSION_FLAG,
ORIGINAL_STRING:detail::VARIANT                                     AS  DETAIL_INFO,
ORIGINAL_STRING:source::VARCHAR                                     AS  DST_SERVICE_NAME    ,
ORIGINAL_STRING:detail:recipientAccountId::VARCHAR                            AS  DST_USER_ID  ,
'AWS'                                                   AS  DVC_PRODUCT,
'Amazon'                                                AS  DVC_VENDOR,
'*'                                                   AS  DVC_VERSION,
ORIGINAL_STRING:detail:errorCode::VARCHAR                               AS  ERROR_CODE  ,
ORIGINAL_STRING:detail:errorMessage::VARCHAR                              AS  ERROR_DESC   ,
ORIGINAL_STRING:detail:eventCategory::VARCHAR                             AS  EVENT_CAT_NAME  ,
ORIGINAL_STRING:detail:eventID::VARCHAR                                 AS  EVENT_GUID   ,
ORIGINAL_STRING:detail:eventName::VARCHAR                               AS  EVENT_NAME ,
ORIGINAL_STRING:detail:eventSource::VARCHAR                               AS  EVENT_SERVICE_NAME,
ORIGINAL_STRING:time::TIMESTAMP                                     AS  EVENT_TIME  ,
ORIGINAL_STRING:detail:eventType::VARCHAR                               AS  EVENT_TYPE   ,
ORIGINAL_STRING:detail:userIdentity:sessionContext:mfaAuthenticated::BOOLEAN              AS  MFA_SESSION_FLAG ,
ORIGINAL_STRING:detail:userIdentity:sessionContext:creationDate::TIMESTAMP                AS  NEW_USER_SESSION_TIME ,
ORIGINAL_STRING:detail:readOnly::BOOLEAN                                AS  READONLY_FLAG  ,
ORIGINAL_STRING:region::VARCHAR                                     AS  REGION_NAME,
ORIGINAL_STRING:detail:requestParameters:Action::VARCHAR                        AS  REQUEST_ACTION_CODE ,
ORIGINAL_STRING:detail:requestParameters:Arn::VARCHAR                         AS  REQUEST_ARN ,
ORIGINAL_STRING:detail:requestParameters:CallerArn::VARCHAR                       AS  REQUEST_CALLER_ARN  ,
ORIGINAL_STRING:detail:requestParameters:Description::VARCHAR                     AS  REQUEST_DESCRIPTION  ,
ORIGINAL_STRING:detail:requestParameters:GroupName::VARCHAR                       AS  REQUEST_GROUP_NAME   ,
ORIGINAL_STRING:detail:requestParameters:NewGroupName::VARCHAR                      AS  REQUEST_GROUP_NAME_NEW  ,
ORIGINAL_STRING:detail:requestID::VARCHAR                               AS  REQUEST_GUID  ,
ORIGINAL_STRING:detail:requestParameters::VARCHAR                           AS  REQUEST_INFO  ,
ORIGINAL_STRING:detail:requestParameters:InstanceProfileName::VARCHAR                 AS  REQUEST_INSTANCE_PROFILE_NAME  ,
ORIGINAL_STRING:detail:requestParameters:MaxItems::VARCHAR                        AS  REQUEST_ITEM_COUNT_MAX         ,
ORIGINAL_STRING:detail:requestParameters:JobId::VARCHAR                         AS  REQUEST_JOB_ID ,
ORIGINAL_STRING:detail:requestParameters:Marker::VARCHAR                        AS  REQUEST_MARKER         ,
ORIGINAL_STRING:detail:requestParameters:Name::VARCHAR                          AS  REQUEST_NAME  ,
ORIGINAL_STRING:detail:requestParameters:Path::VARCHAR                          AS  REQUEST_PATH   ,
ORIGINAL_STRING:detail:requestParameters:NewPath::VARCHAR                       AS  REQUEST_PATH_NEW  ,
ORIGINAL_STRING:detail:requestParameters:PathPrefix::VARCHAR                      AS  REQUEST_PATH_PREFIX  ,
ORIGINAL_STRING:detail:requestParameters:Policy::VARIANT                        AS  REQUEST_POLICY    ,
ORIGINAL_STRING:detail:requestParameters:PolicyArn::VARCHAR                       AS  REQUEST_POLICY_ARN    ,
ORIGINAL_STRING:detail:requestParameters:PolicyArns::VARIANT                      AS  REQUEST_POLICY_ARN_LIST   ,
ORIGINAL_STRING:detail:requestParameters:PolicyDocument::VARIANT                    AS  REQUEST_POLICY_DOCUMENT    ,
ORIGINAL_STRING:detail:requestParameters:PolicyInputList::VARIANT                   AS  REQUEST_POLICY_LIST    ,
ORIGINAL_STRING:detail:requestParameters:PolicyName::VARCHAR                      AS  REQUEST_POLICY_NAME  ,
ORIGINAL_STRING:detail:requestParameters:VersionId::VARCHAR                       AS  REQUEST_POLICY_VERSION_ID  ,
ORIGINAL_STRING:detail:requestParameters:RoleArn::VARCHAR                       AS  REQUEST_ROLE_ARN  ,
ORIGINAL_STRING:detail:requestParameters:RoleName::VARCHAR                        AS  REQUEST_ROLE_NAME     ,
ORIGINAL_STRING:detail:requestParameters:SerialNumber::VARCHAR                      AS  REQUEST_SERIAL_NUMBER   ,
ORIGINAL_STRING:detail:requestParameters:ServerCertificateName::VARCHAR                 AS  REQUEST_SERVER_CERTIFICATE_NAME,
NVL(ORIGINAL_STRING:detail:requestParameters:ServerCertificateName::VARCHAR , ORIGINAL_STRING:detail:requestParameters:ServiceName::VARCHAR)                                                     AS  REQUEST_SERVICE_NAME,
ORIGINAL_STRING:detail:requestParameters:RoleSessionName::VARCHAR                   AS  REQUEST_SESSION_NAME ,
ORIGINAL_STRING:detail:requestParameters:SortKey::VARCHAR                       AS  REQUEST_SORT_KEY ,
ORIGINAL_STRING:detail:requestParameters:SourceIdentity::VARCHAR                    AS  REQUEST_SOURCE_IDENTITY   ,
ORIGINAL_STRING:detail:requestParameters:Status::VARCHAR                        AS  REQUEST_STATUS ,
ORIGINAL_STRING:detail:requestParameters:TagKeys::VARIANT                       AS  REQUEST_TAG_KEY_LIST  ,
ORIGINAL_STRING:detail:requestParameters:Tags::VARCHAR                          AS  REQUEST_TAG_LIST ,
ORIGINAL_STRING:detail:requestParameters:UserName::VARCHAR                        AS  REQUEST_USER_NAME,
ORIGINAL_STRING:detail:requestParameters:NewUserName::VARCHAR                     AS  REQUEST_USER_NAME_NEW  ,
NVL(ORIGINAL_STRING:resources::VARCHAR, ORIGINAL_STRING:detail:resources::VARCHAR)            AS  RESOURCE_LIST    ,
ORIGINAL_STRING:detail:responseElements:AccountAliases::VARCHAR                     AS  RESPONSE_ALIAS_LIST ,
ORIGINAL_STRING:detail:responseElements:Account::VARCHAR                        AS  RESPONSE_ACCOUNT,
ORIGINAL_STRING:detail:responseElements:Arn::VARCHAR                          AS  RESPONSE_ARN ,
ORIGINAL_STRING:detail:responseElements:AssumedRoleUser::VARIANT                    AS  RESPONSE_ASSUMED_USER_INFO ,
ORIGINAL_STRING:detail:responseElements:ClientIDList::VARIANT                                         AS  RESPONSE_CLIENT_LIST ,
ORIGINAL_STRING:detail:responseElements:ConsoleLogin::VARCHAR                     AS  RESPONSE_CONSOLE_LOGIN_FLAG,
ORIGINAL_STRING:detail:responseElements:ContextKeyNames::VARIANT                    AS  RESPONSE_CONTEXT_KEY_NAME_LIST ,
NVL(ORIGINAL_STRING:detail:responseElements:Error:Code::VARCHAR,ORIGINAL_STRING:detail:responseElements:ErrorDetails:Code::VARCHAR)                 AS  RESPONSE_ERROR_CODE,
NVL(ORIGINAL_STRING:detail:responseElements:Error:Message::VARCHAR,NVL(ORIGINAL_STRING:detail:responseElements:ErrorDetails:Message::VARCHAR,ORIGINAL_STRING:detail:responseElements:Reason::VARCHAR))                                        AS  RESPONSE_ERROR_MESSAGE,
ORIGINAL_STRING:detail:responseElements:Group::VARIANT                          AS  RESPONSE_GROUP_INFO,
NVL(ORIGINAL_STRING:detail:responseElements:GroupDetailList::VARIANT,ORIGINAL_STRING:detail:responseElements:Groups::VARIANT)     AS  RESPONSE_GROUP_LIST,
ORIGINAL_STRING:detail:responseElements:GroupName::VARCHAR                        AS  RESPONSE_GROUP_NAME ,
ORIGINAL_STRING:detail:responseElements::VARIANT                            AS  RESPONSE_INFO  ,
ORIGINAL_STRING:detail:responseElements:JobCompletionDate::TIMESTAMP_NTZ(9)               AS  RESPONSE_JOB_END_TIME ,
ORIGINAL_STRING:detail:responseElements:JobId::VARCHAR                            AS  RESPONSE_JOB_ID ,
ORIGINAL_STRING:detail:responseElements:JobStatus::VARCHAR                        AS  RESPONSE_JOB_STATUS ,
ORIGINAL_STRING:detail:responseElements:JobType::VARCHAR                        AS  RESPONSE_JOB_TYPE ,
ORIGINAL_STRING:detail:responseElements:LoginProfile::VARIANT                     AS  RESPONSE_LOGIN_INFO ,
ORIGINAL_STRING:detail:responseElements:Marker::VARCHAR                         AS  RESPONSE_MARKER          ,
ORIGINAL_STRING:detail:responseElements:SummaryMap::VARIANT                       AS  RESPONSE_METRICS ,
ORIGINAL_STRING:detail:responseElements:MFADevices::VARIANT                       AS  RESPONSE_MFA_LIST,
ORIGINAL_STRING:detail:responseElements:PasswordUpdated::VARCHAR                    AS  RESPONSE_PASSWORD_UPDATED_RESULT,
ORIGINAL_STRING:detail:responseElements:PolicyGroups::VARIANT                     AS  RESPONSE_POLICY_GROUP_LIST,
ORIGINAL_STRING:detail:responseElements:PolicyName::VARCHAR                       AS  RESPONSE_POLICY_NAME ,
ORIGINAL_STRING:detail:responseElements:PolicyNames::VARIANT                      AS  RESPONSE_POLICY_NAME_LIST  ,
ORIGINAL_STRING:detail:responseElements:PolicyRoles::VARIANT                      AS  RESPONSE_POLICY_ROLE_LIST,
ORIGINAL_STRING:detail:responseElements:PolicyUsers::VARIANT                      AS  RESPONSE_POLICY_USER_LIST,
NVL(ORIGINAL_STRING:detail:responseElements:PolicyVersion::VARIANT,ORIGINAL_STRING:detail:responseElements:Versions::VARIANT)     AS  RESPONSE_POLICY_VERSION,
ORIGINAL_STRING:detail:responseElements:Provider::VARCHAR                       AS  RESPONSE_PROVIDER,
ORIGINAL_STRING:detail:responseElements:Role::VARIANT                         AS  RESPONSE_ROLE ,
NVL(ORIGINAL_STRING:detail:responseElements:RoleDetailList::VARIANT,ORIGINAL_STRING:detail:responseElements:Roles::VARIANT)       AS  RESPONSE_ROLE_LIST,
ORIGINAL_STRING:detail:responseElements:RoleName::VARCHAR                       AS  RESPONSE_ROLE_NAME ,
ORIGINAL_STRING:detail:responseElements:ValidUntil::TIMESTAMP_NTZ(9)                  AS  RESPONSE_SAML_END_TIME,
ORIGINAL_STRING:detail:responseElements:Status::VARCHAR                         AS  RESPONSE_STATUS ,
ORIGINAL_STRING:detail:responseElements:Subject::VARCHAR                        AS  RESPONSE_SUBJECT,
ORIGINAL_STRING:detail:responseElements:Tags::VARIANT                         AS  RESPONSE_TAGS   ,
ORIGINAL_STRING:detail:responseElements:IsTruncated::BOOLEAN                      AS  RESPONSE_TRUNCATED_FLAG          ,
ORIGINAL_STRING:detail:responseElements:Url::VARCHAR                          AS  RESPONSE_URL ,
NVL(ORIGINAL_STRING:detail:responseElements:User::VARIANT,ORIGINAL_STRING:detail:responseElements:UserDetailList::VARIANT)        AS  RESPONSE_USER_INFO,
ORIGINAL_STRING:detail:responseElements:Users::VARIANT                          AS  RESPONSE_USER_LIST , 
ORIGINAL_STRING:detail:responseElements:UserName::VARCHAR                       AS  RESPONSE_USER_NAME ,
ORIGINAL_STRING:detail:responseElements:UserId::VARCHAR                         AS  RESPONSE_USER_SID,
ORIGINAL_STRING:detail:responseElements:VirtualMFADevice::VARIANT                   AS  RESPONSE_VIRTUAL_MFA_DEVICE_INFO ,
ORIGINAL_STRING:detail:serviceEventDetails::VARIANT                           AS  SERVICE_EVENT_DETAILS  ,
ORIGINAL_STRING:detail:sharedEventID::VARCHAR                             AS  SHARED_EVENT_GUID    ,
ORIGINAL_STRING:detail:sourceIPAddress::VARCHAR                             AS  SRC_IP ,
ORIGINAL_STRING:detail:userIdentity:invokedBy::VARCHAR                          AS  SRC_SERVICE_NAME ,
'AWS IAM STS Console'                                                 AS  SRC_TYPE,
ORIGINAL_STRING:detail:userIdentity:arn::VARCHAR                            AS  SRC_USER_ARN ,
ORIGINAL_STRING:detail:userIdentity:accountId::VARCHAR                          AS  SRC_USER_ID ,
ORIGINAL_STRING:detail:userIdentity::VARIANT                              AS  SRC_USER_INFO  ,
ORIGINAL_STRING:detail:userIdentity:userName::VARCHAR                         AS  SRC_USER_NAME  ,
ORIGINAL_STRING:detail:userIdentity:sessionContext:sessionIssuer:arn::VARCHAR             AS  SRC_USER_SESSION_CONTEXT_ISSUER_ACCOUNT_ARN ,
ORIGINAL_STRING:detail:userIdentity:sessionContext:sessionIssuer:accountId::VARCHAR           AS  SRC_USER_SESSION_CONTEXT_ISSUER_ACCOUNT_ID ,
ORIGINAL_STRING:detail:userIdentity:sessionContext:sessionIssuer::VARIANT               AS  SRC_USER_SESSION_CONTEXT_ISSUER_INFO,
ORIGINAL_STRING:detail:userIdentity:sessionContext:sessionIssuer:principalId::VARCHAR         AS  SRC_USER_SESSION_CONTEXT_ISSUER_PRINCIPAL_ID ,
ORIGINAL_STRING:detail:userIdentity:sessionContext:sessionIssuer:type::VARCHAR              AS  SRC_USER_SESSION_CONTEXT_ISSUER_TYPE ,
ORIGINAL_STRING:detail:userIdentity:sessionContext:sessionIssuer:userName::VARCHAR            AS  SRC_USER_SESSION_CONTEXT_ISSUER_USER_NAME ,
ORIGINAL_STRING:detail:userIdentity:sessionContext::VARIANT                       AS  SRC_USER_SESSION_INFO  ,
ORIGINAL_STRING:detail:userIdentity:sessionIssuer::VARIANT                        AS  SRC_USER_SESSION_ISSUER_INFO ,
ORIGINAL_STRING:detail:userIdentity:principalId::VARCHAR                        AS  SRC_USER_SID ,
ORIGINAL_STRING:detail:userIdentity:type::VARCHAR                           AS  SRC_USER_TYPE    ,
ORIGINAL_STRING:detail:tlsDetails::VARIANT                                AS  TLS_INFO   ,
ORIGINAL_STRING:detail:userAgent::VARCHAR                               AS  USERAGENT    ,
ORIGINAL_STRING:detail:vpcEndpointId::VARCHAR                             AS  VPC_ENDPOINT_ID 
from EA_SECURITY_DATALAKE.RAW.AMZ_AWS_CLOUDTRAIL
where original_string:source = 'aws.iam';










CREATE OR REPLACE VIEW AMZ_AWS_GUARDDUTYFINDINGS_ODM AS
SELECT
ORIGINAL_STRING,
CASE WHEN ORIGINAL_STRING:detail:accountId IS NOT NULL
    THEN ORIGINAL_STRING:detail:accountId::VARCHAR
  WHEN ORIGINAL_STRING:account IS NOT NULL
    THEN ORIGINAL_STRING:account::VARCHAR 
  ELSE '000000000000' end AS ACCOUNT_ID,
COMMIT_TIME,
GUID,
ORIGINAL_STRING:detail AS DETAIL,
ORIGINAL_STRING:detail:service:action:awsApiCallAction:api::VARCHAR AS ACTION_APICALL_NAME,
ORIGINAL_STRING:detail:service:action:awsApiCallAction:domainDetails:domain::VARCHAR AS ACTION_APICALL_DOMAIN,
ORIGINAL_STRING:detail:service:action:awsApiCallAction::VARIANT AS ACTION_APICALL_INFO,
ORIGINAL_STRING:detail:service:action:awsApiCallAction:errorCode::VARCHAR AS ACTION_ERROR_CODE,
ORIGINAL_STRING:detail:service:action::VARIANT AS ACTION_INFO,
ORIGINAL_STRING:detail:service:action:actionType::VARCHAR AS ACTION_TYPE,
ORIGINAL_STRING:detail:service:additionalInfo:anomalies:anomalousAPIs::VARIANT AS ANOMALITY_API_LIST,
ORIGINAL_STRING:detail:service:archived::BOOLEAN AS ARCHIVED_FLAG,
ORIGINAL_STRING:detail:service:action:networkConnectionAction:blocked::BOOLEAN AS CONNECTION_BLOCKED_FLAG,
ORIGINAL_STRING:detail:service:action:networkConnectionAction:connectionDirection::VARCHAR AS CONNECTION_DIRECTION,
ORIGINAL_STRING:detail:service:action:networkConnectionAction::VARIANT AS CONNECTION_INFO,
ORIGINAL_STRING:detail:service:action:networkConnectionAction:protocol::VARCHAR AS CONNECTION_PROTO,
ORIGINAL_STRING:detail:createdAt::TIMESTAMP AS CREATE_TIME,
ORIGINAL_STRING:detail:service:detectorId::VARCHAR AS DETECTOR_ID,
ORIGINAL_STRING:detail:service:action:dnsRequestAction:blocked::BOOLEAN AS DNS_BLOCKED_FLAG,
ORIGINAL_STRING:detail:service:evidence::VARIANT AS DNS_FINDING_EVIDENCE,
ORIGINAL_STRING:detail:service:action:dnsRequestAction:protocol::VARCHAR AS DNS_PROTO,
ORIGINAL_STRING:detail:service:action:dnsRequestAction:domain::VARCHAR AS DNS_QUERY,
ORIGINAL_STRING:detail:resource:s3BucketDetails::VARIANT AS DST_BUCKET_INFO,
ORIGINAL_STRING:detail:resource:instanceDetails:availabilityZone::VARCHAR AS DST_INSTANCE_AVAILABILITY_ZONE,
ORIGINAL_STRING:detail:resource:instanceDetails:instanceId::VARCHAR AS DST_INSTANCE_ID,
ORIGINAL_STRING:detail:resource:instanceDetails:imageDescription::VARCHAR AS DST_INSTANCE_IMAGE_DESC,
ORIGINAL_STRING:detail:resource:instanceDetails:imageId::VARCHAR AS DST_INSTANCE_IMAGE_ID,
ORIGINAL_STRING:detail:resource:instanceDetails::VARIANT AS DST_INSTANCE_INFO,
ORIGINAL_STRING:detail:resource:instanceDetails:launchTime::TIMESTAMP_NTZ(9) AS DST_INSTANCE_LAUNCH_TIME,
ORIGINAL_STRING:detail:resource:instanceDetails:networkInterfaces::VARIANT AS DST_INSTANCE_NETWORK_LIST,
ORIGINAL_STRING:detail:resource:instanceDetails:outpostArn::VARCHAR AS DST_INSTANCE_OUTPOST_ARN,
ORIGINAL_STRING:detail:resource:instanceDetails:platform::VARCHAR AS DST_INSTANCE_PLATFORM,
ORIGINAL_STRING:detail:resource:instanceDetails:productCodes::VARIANT AS DST_INSTANCE_PRODUCT_LIST,
ORIGINAL_STRING:detail:resource:instanceDetails:iamInstanceProfile:arn::VARCHAR AS DST_INSTANCE_PROFILE_ARN,
ORIGINAL_STRING:detail:resource:instanceDetails:iamInstanceProfile:id::VARCHAR AS DST_INSTANCE_PROFILE_ID,
ORIGINAL_STRING:detail:resource:instanceDetails:instanceState::VARCHAR AS DST_INSTANCE_STATE,
ORIGINAL_STRING:detail:resource:instanceDetails:tags::VARIANT AS DST_INSTANCE_TAG_LIST,
ORIGINAL_STRING:detail:resource:instanceDetails:instanceType::VARCHAR AS DST_INSTANCE_TYPE,
ORIGINAL_STRING:detail:resource::VARIANT AS DST_RESOURCE_INFO,
ORIGINAL_STRING:detail:service:action:awsApiCallAction:affectedResources::VARIANT AS DST_RESOURCE_LIST,
ORIGINAL_STRING:detail:resource:resourceType::VARCHAR AS DST_RESOURCE_TYPE,
'AWS' AS DVC_PRODUCT,
'Amazon' AS DVC_VENDOR,
'*' AS DVC_VERSION,
ORIGINAL_STRING:detail:updatedAt::TIMESTAMP_NTZ(9) AS FINDING_UPDATE_TIME,
ORIGINAL_STRING:detail:service:additionalInfo::VARIANT AS EXTRA_FINDING_INFO,
CASE WHEN (ORIGINAL_STRING:detail:arn IS NOT NULL)
      THEN ORIGINAL_STRING:detail:arn::VARCHAR
    WHEN (ORIGINAL_STRING:detail:userIdentity:arn IS NOT NULL)
      THEN ORIGINAL_STRING:detail:userIdentity:arn::VARCHAR
    WHEN (ORIGINAL_STRING:detail:userIdentity:sessionIssuer:arn IS NOT NULL)
      THEN ORIGINAL_STRING:detail:userIdentity:sessionIssuer:arn end AS FINDING_ARN,
ORIGINAL_STRING:detail:service:count::NUMBER AS FINDING_COUNT,
ORIGINAL_STRING:detail:description::VARCHAR AS FINDING_DESC,
ORIGINAL_STRING:detail:service:userFeedback::VARCHAR AS FINDING_FEEDBACK,
ORIGINAL_STRING:id::VARCHAR AS FINDING_ID,
ORIGINAL_STRING:detail:service::VARIANT AS FINDING_INFO,
ORIGINAL_STRING:detail:schemaVersion::VARCHAR AS FINDING_SCHEMA_VERSION,
ORIGINAL_STRING:detail:title::VARCHAR AS FINDING_TITLE,
CASE WHEN (ORIGINAL_STRING:detail:type IS NOT NULL)
    THEN ORIGINAL_STRING:detail:type::VARCHAR
  WHEN (ORIGINAL_STRING:detail:userIdentity:type IS NOT NULL)
    THEN ORIGINAL_STRING:detail:userIdentity:type::VARCHAR
  WHEN (ORIGINAL_STRING:detail:eventType IS NOT NULL)
    THEN ORIGINAL_STRING:detail:eventType::VARCHAR END AS FINDING_TYPE,
ORIGINAL_STRING:detail:service:eventFirstSeen::TIMESTAMP_NTZ(9) AS FIRST_EVENT_TIME,
ORIGINAL_STRING:detail:service:eventLastSeen::TIMESTAMP_NTZ(9) AS LAST_EVENT_TIME,
ORIGINAL_STRING:detail:eventTime::TIMESTAMP_NTZ(9) AS EVENT_TIME,
ORIGINAL_STRING:detail:service:action:networkConnectionAction:localIpDetails:ipAddressV4::VARCHAR AS LOCAL_IP,
ORIGINAL_STRING:detail:service:action:networkConnectionAction:localPortDetails:port::NUMBER(6,0) AS LOCAL_PORT,
ORIGINAL_STRING:detail:service:action:networkConnectionAction:localPortDetails:portName::VARCHAR AS LOCAL_PORT_NAME,
ORIGINAL_STRING:PARSING_TIME::TIMESTAMP AS PARSING_TIME,
ORIGINAL_STRING:detail:partition::VARCHAR AS PARTITION,
ORIGINAL_STRING:detail:service:action:portProbeAction:blocked::BOOLEAN AS PORT_PROBE_BLOCKED_FLAG,
ORIGINAL_STRING:detail:service:action:portProbeAction::VARIANT AS PORT_PROBE_INFO,
ORIGINAL_STRING:detail:service:action:portProbeAction:portProbeDetails::VARIANT AS PORT_PROBE_LIST,
ORIGINAL_STRING:detail:service:additionalInfo:profiledBehavior::VARIANT AS PROFILED_BEHAVIOR_INFO,
CASE WHEN (ORIGINAL_STRING:detail:region IS NOT NULL)
    THEN ORIGINAL_STRING:detail:region::VARCHAR
  WHEN (ORIGINAL_STRING:region IS NOT NULL)
    THEN ORIGINAL_STRING:region::VARCHAR
  WHEN (ORIGINAL_STRING:detail:awsRegion IS NOT NULL)
    THEN ORIGINAL_STRING:detail:awsRegion::VARCHAR END AS REGION_NAME,
ORIGINAL_STRING:detail:service:action:networkConnectionAction:remoteIpDetails:city:cityName::VARCHAR AS REMOTE_GEO_CITY,
ORIGINAL_STRING:detail:service:action:networkConnectionAction:remoteIpDetails:country:countryName::VARCHAR AS REMOTE_GEO_COUNTRY,
ORIGINAL_STRING:detail:service:action:networkConnectionAction:remoteIpDetails:geoLocation:lat::NUMBER(6,3) AS REMOTE_GEO_LAT,
ORIGINAL_STRING:detail:service:action:networkConnectionAction:remoteIpDetails:geoLocation:lon::NUMBER(6,3) AS REMOTE_GEO_LONG,
ORIGINAL_STRING:detail:service:action:networkConnectionAction:remoteIpDetails:ipAddressV4::VARCHAR AS REMOTE_IP,
ORIGINAL_STRING:detail:service:action:networkConnectionAction:remoteIpDetails:organization:asn::VARCHAR AS REMOTE_IP_ASN,
ORIGINAL_STRING:detail:service:action:networkConnectionAction:remoteIpDetails::VARIANT AS REMOTE_IP_INFO,
ORIGINAL_STRING:detail:service:action:networkConnectionAction:remoteIpDetails:organization:isp::VARCHAR AS REMOTE_IP_ISP,
ORIGINAL_STRING:detail:service:action:networkConnectionAction:remoteIpDetails:organization:org::VARCHAR AS REMOTE_IP_ORG_NAME,
ORIGINAL_STRING:detail:service:action:networkConnectionAction:remotePortDetails:port::NUMBER(6,0) AS REMOTE_PORT,
ORIGINAL_STRING:detail:service:action:networkConnectionAction:remotePortDetails:portName::VARCHAR AS REMOTE_PORT_NAME,
ORIGINAL_STRING:ALERT_JSON::VARIANT AS RISK_DESC,
ORIGINAL_STRING:detail:service:additionalInfo:portsScannedSample::VARIANT AS SCANNED_PORT_LIST,
ORIGINAL_STRING:detail:severity::NUMBER AS SEVERITY_NUMBER,
ORIGINAL_STRING:detail:resource:accessKeyDetails::VARIANT AS SRC_ACCESS_KEY_INFO,
ORIGINAL_STRING:detail:service:action:awsApiCallAction:remoteIpDetails:organization:asn::VARCHAR AS SRC_CALLER_ASN,
ORIGINAL_STRING:detail:service:action:awsApiCallAction:serviceName::VARCHAR AS SRC_CALLER_DOMAIN_NAME,
ORIGINAL_STRING:detail:service:action:awsApiCallAction:remoteIpDetails:city:cityName::VARCHAR AS SRC_CALLER_GEO_CITY,
ORIGINAL_STRING:detail:service:action:awsApiCallAction:remoteIpDetails:country:countryName::VARCHAR AS SRC_CALLER_GEO_COUNTRY,
ORIGINAL_STRING:detail:service:action:awsApiCallAction:remoteIpDetails:geoLocation:lat::NUMBER(6,3) AS SRC_CALLER_GEO_LAT,
ORIGINAL_STRING:detail:service:action:awsApiCallAction:remoteIpDetails:geoLocation:lon::NUMBER(6,3) AS SRC_CALLER_GEO_LONG,
ORIGINAL_STRING:detail:service:action:awsApiCallAction:remoteIpDetails:ipAddressV4::VARCHAR AS SRC_CALLER_IP,
ORIGINAL_STRING:detail:service:action:awsApiCallAction:remoteIpDetails::VARIANT AS SRC_CALLER_IP_INFO,
ORIGINAL_STRING:detail:service:action:awsApiCallAction:remoteIpDetails:organization:isp::VARCHAR AS SRC_CALLER_ISP,
ORIGINAL_STRING:detail:service:action:awsApiCallAction:remoteIpDetails:organization:org::VARCHAR AS SRC_CALLER_ORG_NAME,
ORIGINAL_STRING:detail:service:action:awsApiCallAction:callerType::VARCHAR AS SRC_CALLER_TYPE,
ORIGINAL_STRING:detail:service:resourceRole::VARCHAR AS SRC_RESOURCE_ROLE,
ORIGINAL_STRING:detail:service:serviceName::VARCHAR AS SRC_SERVICE_NAME,
'GuardDuty Finding' AS SRC_TYPE,
ORIGINAL_STRING:detail:resource:accessKeyDetails:userName::VARCHAR AS SRC_USER_NAME,
ORIGINAL_STRING:detail:resource:accessKeyDetails:userType::VARCHAR AS SRC_USER_TYPE,
ORIGINAL_STRING:detail:service:evidence:threatIntelligenceDetails::VARIANT AS THREAT_LIST,
ORIGINAL_STRING:detail:service:additionalInfo:unusual::VARIANT AS UNUSUAL_ACTIVITY_INFO,
ORIGINAL_STRING:detail:service:additionalInfo:unusualBehavior::VARIANT AS UNUSUAL_BEHAVIOR_INFO,
ORIGINAL_STRING:detail:service:additionalInfo:unusualProtocol::VARCHAR AS UNUSUAL_PROTOCOL,
ORIGINAL_STRING:detail:service:additionalInfo:userAgent:fullUserAgent::VARCHAR AS USERAGENT,
ORIGINAL_STRING:detail:service:additionalInfo:userAgent:userAgentCategory::VARCHAR AS USERAGENT_CAT,
l1.value:name as S3,
l2.value:privateIpAddress as PRIVATE_IP,
l2.value:publicIp as PUBLIC_IP
from EA_SECURITY_DATALAKE.RAW.AMZ_AWS_GUARDDUTY,
lateral flatten(ORIGINAL_STRING:detail:resource:s3BucketDetails, outer => true)l1,
lateral flatten(ORIGINAL_STRING:detail:resource:instanceDetails:networkInterfaces, outer => true)l2;






CREATE  VIEW if not exists AMZ_AWS_CLOUDTRAIL_ODM AS
SELECT
GUID                                                                                                    AS  GUID,
ORIGINAL_STRING,
COMMIT_TIME,
ORIGINAL_STRING:account::VARCHAR                                    AS  ACCOUNT_ID,
ORIGINAL_STRING:detail:userIdentity:arn::VARCHAR                            AS  SRC_USER_ARN ,
ORIGINAL_STRING:detail:userIdentity:accountId::VARCHAR                          AS  SRC_USER_ID ,
ORIGINAL_STRING:detail:userIdentity::VARIANT                              AS  SRC_USER_INFO  ,
split_part(ORIGINAL_STRING:detail:userIdentity:arn, '/', -1)::VARCHAR                   AS  SRC_USER_NAME  ,
ORIGINAL_STRING:detail:userIdentity:sessionContext:sessionIssuer:arn::VARCHAR             AS  SRC_USER_SESSION_CONTEXT_ISSUER_ACCOUNT_ARN ,
ORIGINAL_STRING:detail:userIdentity:sessionContext:sessionIssuer:accountId::VARCHAR           AS  SRC_USER_SESSION_CONTEXT_ISSUER_ACCOUNT_ID ,
ORIGINAL_STRING:detail:userIdentity:sessionContext:sessionIssuer::VARIANT               AS  SRC_USER_SESSION_CONTEXT_ISSUER_INFO,
ORIGINAL_STRING:detail:userIdentity:sessionContext:sessionIssuer:principalId::VARCHAR         AS  SRC_USER_SESSION_CONTEXT_ISSUER_PRINCIPAL_ID ,
ORIGINAL_STRING:detail:userIdentity:sessionContext:sessionIssuer:type::VARCHAR              AS  SRC_USER_SESSION_CONTEXT_ISSUER_TYPE ,
ORIGINAL_STRING:detail:userIdentity:sessionContext:sessionIssuer:userName::VARCHAR            AS  SRC_USER_SESSION_CONTEXT_ISSUER_USER_NAME ,
ORIGINAL_STRING:detail:userIdentity:sessionContext::VARIANT                       AS  SRC_USER_SESSION_INFO  ,
ORIGINAL_STRING:detail:userIdentity:sessionIssuer::VARIANT                        AS  SRC_USER_SESSION_ISSUER_INFO ,
ORIGINAL_STRING:detail:userIdentity:principalId::VARCHAR                        AS  SRC_USER_SID ,
ORIGINAL_STRING:detail:userIdentity:type::VARCHAR                           AS  SRC_USER_TYPE    ,
ORIGINAL_STRING:detail:managementEvent::BOOLEAN                             AS  ADMIN_FLAG,
ORIGINAL_STRING:"detail-type"::VARCHAR                                  AS  AWS_DETAIL_TYPE,
ORIGINAL_STRING:detail:eventVersion::VARCHAR                              AS  AWS_EVENT_VERSION,
ORIGINAL_STRING:detail::VARIANT                                     AS  DETAIL_INFO,
ORIGINAL_STRING:source::VARCHAR                                     AS  DST_SERVICE_NAME,
ORIGINAL_STRING:detail:recipientAccountId::VARCHAR                            AS  DST_USER_ID  ,
'AWS'                                                   AS  DVC_PRODUCT,
'Amazon'                                                AS  DVC_VENDOR,
'*'                                                   AS  DVC_VERSION,
ORIGINAL_STRING:detail:errorCode::VARCHAR                               AS  ERROR_CODE  ,
ORIGINAL_STRING:detail:errorMessage::VARCHAR                              AS  ERROR_DESC   ,
ORIGINAL_STRING:detail:eventCategory::VARCHAR                             AS  EVENT_CAT_NAME  ,
ORIGINAL_STRING:detail:eventID::VARCHAR                                 AS  EVENT_GUID   ,
ORIGINAL_STRING:detail:eventName::VARCHAR                               AS  EVENT_NAME ,
ORIGINAL_STRING:detail:eventSource::VARCHAR                               AS  EVENT_SERVICE_NAME,
ORIGINAL_STRING:time::TIMESTAMP                                     AS  EVENT_TIME  ,
ORIGINAL_STRING:detail:eventType::VARCHAR                               AS  EVENT_TYPE   ,
ORIGINAL_STRING:detail:requestID::VARCHAR                               AS  REQUEST_GUID  ,
ORIGINAL_STRING:detail:requestParameters::VARIANT                           AS  REQUEST_INFO  ,
ORIGINAL_STRING:detail:responseElements::VARIANT                            AS  RESPONSE_INFO  ,
ORIGINAL_STRING:detail:userIdentity:sessionContext:mfaAuthenticated::BOOLEAN              AS  MFA_SESSION_FLAG ,
ORIGINAL_STRING:detail:userIdentity:sessionContext:creationDate::TIMESTAMP                AS  NEW_USER_SESSION_TIME ,
ORIGINAL_STRING:detail:readOnly::BOOLEAN                                AS  READONLY_FLAG  ,
ORIGINAL_STRING:region::VARCHAR                                     AS  REGION_NAME,
ORIGINAL_STRING:detail:sourceIPAddress::VARCHAR                             AS  SRC_IP ,
ORIGINAL_STRING:detail:userIdentity:invokedBy::VARCHAR                          AS  SRC_SERVICE_NAME ,
ORIGINAL_STRING:detail:eventType::VARCHAR                                       AS  SRC_TYPE,
ORIGINAL_STRING:detail:userAgent::VARCHAR                               AS  USERAGENT,
ORIGINAL_STRING:detail:insightDetails::VARIANT                            AS  INSIGHT_DETAILS
from EA_SECURITY_DATALAKE.RAW.AMZ_AWS_CLOUDTRAIL;
