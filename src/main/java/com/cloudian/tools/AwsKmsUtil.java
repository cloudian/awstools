/**
 * 
 */

package com.cloudian.tools;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.DescribeKeyRequest;
import com.amazonaws.services.kms.model.DescribeKeyResult;
import com.amazonaws.services.kms.model.KeyListEntry;
import com.amazonaws.services.kms.model.KeyMetadata;
import com.amazonaws.services.kms.model.ListKeysRequest;
import com.amazonaws.services.kms.model.ListKeysResult;
import com.amazonaws.services.kms.model.ScheduleKeyDeletionRequest;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneId;

import org.apache.commons.codec.binary.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Contains utility tools used for AWS KMS.
 * @author garyo
 *
 */
public class AwsKmsUtil {
  private static Logger logger = LogManager.getLogger(AwsKmsUtil.class);

  /**
   * Schedule the deletion of keys older than "oldKeysDays".
   * AWS credentials can be set in homedir/.aws directory (config and credentials files).
   */
  private static void scheduleOldKeyDeletion() {   
    final int pendingWaitPeriodDays = 7;
    final int oldKeysDays = 3;
    final int maxKeys = 1000;

    logger.info("Starting AWS KMS key deletion of keys older than {} days:", oldKeysDays);
    AWSKMS kms = AWSKMSClientBuilder.defaultClient();    
    ListKeysResult result = kms.listKeys(new ListKeysRequest().withLimit(maxKeys));
    int numKeys = 0;
    logger.info("  processing {} keys", result.getKeys().size());
    for (KeyListEntry entry : result.getKeys()) {
      String keyId = entry.getKeyId();
      DescribeKeyRequest dkReq = new DescribeKeyRequest().withKeyId(keyId);
      DescribeKeyResult res = kms.describeKey(dkReq);
      KeyMetadata md = res.getKeyMetadata();
      if (StringUtils.equals("Enabled", md.getKeyState())
          && md.getDescription().startsWith("crn:hs:s3:::")) {
        Duration duration = Duration.between(md.getCreationDate().toInstant()
            .atZone(ZoneId.systemDefault()).toLocalDateTime(), LocalDateTime.now());
        if (duration.toDays() > oldKeysDays) {
          numKeys++;
          logger.info("{}: {}", numKeys, keyId);
          ScheduleKeyDeletionRequest skReq = new ScheduleKeyDeletionRequest().withKeyId(keyId)
              .withPendingWindowInDays(pendingWaitPeriodDays);
          kms.scheduleKeyDeletion(skReq);
        }
      }
    }
    logger.info("Done. {} keys scheduled for deletion", numKeys);
  }


  /**
   * Main way to run the utility tools.
   * @param args Arguments passed into the main method
   */
  public static void main(String[] args) {
    scheduleOldKeyDeletion();
  }
}
