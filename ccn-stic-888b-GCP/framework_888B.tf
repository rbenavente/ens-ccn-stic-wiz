resource "wiz_security_framework" "ens_ccn_stic_888b_framework" {
  name        = "ENS CCN STIC 888B GCP"
  description = "Security Framework based on ENS CCN STIC 888B. The CCN-STIC Guidelines of the National Cryptologic Centre."
  enabled     = true

  # --- OP.ACC: Access Control ---

  category {
    name        = "op.acc.1 - Identification"
    description = "OP ACC- Access Control"

    sub_category {
      title                     = "Identification for Category: High. Level: High"
      cloud_configuration_rules = [
        wiz_cloud_configuration_rule.ccn_888b_op_acc_1_4.id
      ]
      controls                  = [
        "wc-id-966",
        wiz_custom_control.ccn_888b_op_acc_1_2.id,
        wiz_custom_control.ccn_888b_op_acc_1_3.id
      ]
    }
  }

  category {
    name        = "op.acc.3 - Segregation of functions and tasks"
    description = "OP ACC- Access Control"

    sub_category {
      title                     = "Segregation of functions and tasks for Category: High. Level: High"
      cloud_configuration_rules = [
        wiz_cloud_configuration_rule.ccn_888b_op_acc_3_2.id
      ]
      controls                  = [
        "wc-id-623",
        wiz_custom_control.ccn_888b_op_acc_3_3.id
      ]
    }
  }

  category {
    name        = "op.acc.4 - Access rights management process"
    description = "OP ACC- Access Control"

    sub_category {
      title                     = "Access rights management process for Category: High. Level: High"
      cloud_configuration_rules = []
      controls                  = [
        wiz_custom_control.ccn_888b_op_acc_4_1.id,
        wiz_custom_control.ccn_888b_op_acc_4_2.id,
        wiz_custom_control.ccn_888b_op_acc_4_3.id
      ]
    }
  }

  category {
    name        = "op.acc.5 - Authentication mechanism"
    description = "OP ACC- Access Control"

    sub_category {
      title                     = "Authentication mechanism for Category: High. Level: High"
      cloud_configuration_rules = [
        wiz_cloud_configuration_rule.ccn_888b_op_acc_5_1.id,
        wiz_cloud_configuration_rule.ccn_888b_op_acc_5_3.id,
        wiz_cloud_configuration_rule.ccn_888b_op_acc_5_4.id
      ]
      controls                  = [ "wc-id-1820"
      ]
    }
  }

  # --- OP.EXP: Operational Exploitation ---
  category {
    name        = "op.exp.1 - Inventory of assets"
    description = "Operational Exploitation/Maintenance controls."

    sub_category {
      title                     = "Inventory of assets for Category: High. Level: High"
      cloud_configuration_rules = []
      controls                  = [wiz_custom_control.ccn_888b_op_exp_1_1.id]
    }
  }
  category {
    name        = "op.exp.2 - Security settings"
    description = "Operational Exploitation/Maintenance controls."

    sub_category {
      title                     = "Security settings for Category: High. Level: High"
      cloud_configuration_rules = []
      controls                  = []
    }
  }

  category {
    name        = "op.exp.10 - Protection of activity logs"
    description = "Operational Exploitation/Maintenance controls."

    sub_category {
      title                     = "Protection of activity logs for Category: High. Level: High"
      cloud_configuration_rules = [
        wiz_cloud_configuration_rule.ccn_888b_op_exp_10_1.id,
        wiz_cloud_configuration_rule.ccn_888b_op_exp_10_2.id
      ]
      controls                  = []
    }
  }

  category {
    name        = "op.exp.11 - Protection of cryptographic keys"
    description = "Operational Exploitation/Maintenance controls."

    sub_category {
      title                     = "Protection of cryptographic keys for Category: High. Level: High"
      cloud_configuration_rules = [
        wiz_cloud_configuration_rule.ccn_888b_op_exp_11_1.id,
        wiz_cloud_configuration_rule.ccn_888b_op_exp_11_2.id
      ]
      controls                  = []
    }
  }

  # --- Otros: Continuity, Monitoring and Protection ---

  category {
    name        = "op.cont.2 - Continuity of Operations"
    description = "Operational Continuity controls."

    sub_category {
      title                     = "Continuity of Operations for Category: High. Level: High"
      cloud_configuration_rules = []
      controls                  = []
    }
  }

  category {
    name        = "op.mon.1 - Intrusion detection"
    description = "Operational Monitoring controls."

    sub_category {
      title                     = "Intrusion detection for Category: High. Level: High"
      cloud_configuration_rules = []
      controls                  = []
    }
  }

  category {
    name        = "mp.com.2 - Protection of confidentiality"
    description = "Measures of Protection for Communication."

    sub_category {
      title                     = "Protection of confidentiality for Category: High. Level: High"
      cloud_configuration_rules = [
        wiz_cloud_configuration_rule.ccn_888b_op_com_2_1.id
      ]
      controls                  = []
    }
  }

  category {
    name        = "mp.com.4 - Network Segregation"
    description = "Measures of Protection for Communication."

    sub_category {
      title                     = "Network Segregation for Category: High. Level: High"
      cloud_configuration_rules = [
        wiz_cloud_configuration_rule.ccn_888b_op_com_4_1.id
      ]
      controls                  = []
    }
  }

  category {
    name        = "mp.info.3 - Encryption"
    description = "Measures of Protection for Information."

    sub_category {
      title                     = "Encryption for Category: High. Level: High"
      cloud_configuration_rules = [
        wiz_cloud_configuration_rule.ccn_888b_op_info_3_1.id
      ]
      controls                  = []
    }
  }

  category {
    name        = "mp.s.2 - Protection of web services and applications"
    description = "Measures of Protection for Services."

    sub_category {
      title                     = "Protection of web services and applications for Category: High. Level: High"
      cloud_configuration_rules = [
        wiz_cloud_configuration_rule.ccn_888b_op_s_2_1.id
      ]
      controls                  = []
    }
  }

  category {
    name        = "mp.s.8 - Protection against denial of service"
    description = "Measures of Protection for Services."

    sub_category {
      title                     = "Protection against denial of service for Category: High. Level: High"
      cloud_configuration_rules = []
      controls                  = []
    }
  }
}


