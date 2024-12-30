
resource "wiz_security_framework" "ccn_442" {
  description                        = "The CCN-STIC Guidelines of the National Cryptologic Centre can establish specific  compliance  profiles  for  specific  entities  or  sectors,  which  will include  the list of measures and reinforcements that are applicable in each case, or the criteria for their determination"
  enabled                            = true
  maintain_rule_links_from_framework = null
  name                               = "ENS CCN STIC 442 "
  category {
    description = null
    name        = "MP. COM. 3 Authentication protection"
    sub_category {
      cloud_configuration_rules = [wiz_cloud_configuration_rule.ccn_442_mpcom3r1_1.id]
      controls                  = []
      description               = null
      host_configuration_rules  = []
      title                     = " Authentication protection for Classification Level Basic | Medium | High"
    }
    sub_category {
      cloud_configuration_rules = []
      controls                  = []
      description               = null
      host_configuration_rules  = []
      title                     = "Authentication protection for Classification Level Medium "
    }    
    sub_category {
      cloud_configuration_rules = []
      controls                  = []
      description               = null
      host_configuration_rules  = []
      title                     = "Authentication protection for Classification Level High"
    }

  }
  category {
    description = null
    name        = "OP. ACC. 3 Segregation of duties and tasks"
    sub_category {
      cloud_configuration_rules = []
      controls                  = []
      description               = null
      host_configuration_rules  = []
      title                     = "Segregation of duties and tasks for Classification Level  Medium | High"
    }
  }
  category {
    description = null
    name        = "OP. ACC. 7 Remote access"
    sub_category {
      cloud_configuration_rules = []
      controls                  = []
      description               = null
      host_configuration_rules  = []
      title                     = "Remote Access for Classification Level Basic"
    }    
    sub_category {
      cloud_configuration_rules = [wiz_cloud_configuration_rule.ccn_442_acc7r2_1.id]
      controls                  = []
      description               = null
      host_configuration_rules  = []
      title                     = "Remote Access for Classification Level Medium | High"
    }

  }
  category {
    description = null
    name        = "OP. ACC. 4 Access rights management"
    sub_category {
      cloud_configuration_rules = []
      controls                  = []
      description               = null
      host_configuration_rules  = []
      title                     = "Access rights management for Classification Level Basic | Medium | High"
    }
  }
  category {
    description = null
    name        = "MP. COM. 4 Network segregation"
    sub_category {
      cloud_configuration_rules = []
      controls                  = []
      description               = null
      host_configuration_rules  = []
      title                     = "Network segregation for Classification Level High"
    }
  }
  category {
    description = null
    name        = "OP. EXP. 2 Service functionality control to ensure the principle of minimum functionality"
    sub_category {
      cloud_configuration_rules = [ wiz_cloud_configuration_rule.ccn_442_opexp2r1_1.id, wiz_cloud_configuration_rule.ccn_442_opexp2r1_2.id, wiz_cloud_configuration_rule.ccn_442_opexp2r1_3.id, wiz_cloud_configuration_rule.ccn_442_opexp2r1_4.id,
wiz_cloud_configuration_rule.ccn_442_opexp2r1_5.id, wiz_cloud_configuration_rule.ccn_442_opexp2r1_6.id, wiz_cloud_configuration_rule.ccn_442_opexp2r1_7.id, wiz_cloud_configuration_rule.ccn_442_opexp2r1_8.id, wiz_cloud_configuration_rule.ccn_442_opexp2r1_9.id, wiz_cloud_configuration_rule.ccn_442_opexp2r1_10.id, wiz_cloud_configuration_rule.ccn_442_opexp2r1_11.id,wiz_cloud_configuration_rule.ccn_442_opexp2r1_12.id, wiz_cloud_configuration_rule.ccn_442_opexp2r1_13.id, wiz_cloud_configuration_rule.ccn_442_opexp2r1_14.id ,wiz_cloud_configuration_rule.ccn_442_opexp2r1_15.id ,wiz_cloud_configuration_rule.ccn_442_opexp2r1_16.id ,wiz_cloud_configuration_rule.ccn_442_opexp2r1_17.id ,wiz_cloud_configuration_rule.ccn_442_opexp2r1_18.id]
      controls                  = []
      description               = null
      host_configuration_rules  = []
      title                     = "Service functionality control to ensure the principle of minimum functionality  for Classification Level Basic | Medium | High"
    }
  }
  category {
    description = null
    name        = "OP. EXP. 3  Configuration management"
    sub_category {
      cloud_configuration_rules = [wiz_cloud_configuration_rule.ccn_442_opexp3r1_1.id]
      controls                  = []
      description               = null
      host_configuration_rules  = []
      title                     = "Configuration management for Classification Level Basic | Medium | High"
    }
  }
  category {
    description = null
    name        = "OP. EXP. 8 User activity log"
    sub_category {
      cloud_configuration_rules = [wiz_cloud_configuration_rule.ccn_442_opexp8r2_1.id, wiz_cloud_configuration_rule.ccn_442_opexp8r2_2.id,wiz_cloud_configuration_rule.ccn_442_opexp8r2_3.id, wiz_cloud_configuration_rule.ccn_442_opexp8r2_4.id]
      controls                  = []
      description               = null
      host_configuration_rules  = []
      title                     = "User activity log for Classification Level  Medium | High"
    }
  }
  category {
    description = null
    name        = "OP. ACC. 2 Access requirements"
    sub_category {
      cloud_configuration_rules = []
      controls                  = []
      description               = null
      host_configuration_rules  = []
      title                     = "Access Requirements for Classification Level Basic | Medium  | High"
    }
  }
  category {
    description = null
    name        = "OP. ACC. 5 Authentication mechanisms"
     sub_category {
      cloud_configuration_rules = [wiz_cloud_configuration_rule.ccn_442_acc5r1_1.id, terrwiz_cloud_configuration_rule.ccn_442_acc5r1_2.id, wiz_cloud_configuration_rule.ccn_442_acc5r1_3.id, wiz_cloud_configuration_rule.ccn_442_acc5r1_4.id, wiz_cloud_configuration_rule.ccn_442_acc5r1_5.id]
      controls                  = []
      description               = null
      host_configuration_rules  = []
      title                     = "Authentication mechanisms for Classification Level Basic"
    }
    sub_category {
      cloud_configuration_rules = [wiz_cloud_configuration_rule.ccn_442_acc5r2_1.id, wiz_cloud_configuration_rule.ccn_442_acc5r2_2.id, wiz_cloud_configuration_rule.ccn_442_acc5r2_3.id]
      controls                  = []
      description               = null
      host_configuration_rules  = []
      title                     = " Authentication mechanisms for Classification Level Medium"
    }

    sub_category {
      cloud_configuration_rules = [wiz_cloud_configuration_rule.ccn_442_acc5r3_1.id, wiz_cloud_configuration_rule.ccn_442_acc5r3_2.id, wiz_cloud_configuration_rule.ccn_442_acc5r3_3.id]
      controls                  = []
      description               = null
      host_configuration_rules  = []
      title                     = "Authentication mechanisms for Classification Level High"
    }
  }
  category {
    description = null
    name        = "OP. ACC. 6 Local access"

    sub_category {
      cloud_configuration_rules = []
      controls                  = []
      description               = null
      host_configuration_rules  = []
      title                     = "Local Access for Classification Level Basic"
    }    
    sub_category {
      cloud_configuration_rules = []
      controls                  = []
      description               = null
      host_configuration_rules  = []
      title                     = "Local Access for Classification Level Medium"
    }
    
    sub_category {
      cloud_configuration_rules = [wiz_cloud_configuration_rule.ccn_442_acc6r3_1.id, wiz_cloud_configuration_rule.ccn_442_acc6r3_2.id]
      controls                  = []
      description               = null
      host_configuration_rules  = []
      title                     = "Local Access for Classification Level High"
    }


  }
  category {
    description = null
    name        = "MP. INFO. 9 Backups"
    sub_category {
      cloud_configuration_rules = []
      controls                  = []
      description               = null
      host_configuration_rules  = []
      title                     = "Backups for Classification Level Basic | Medium | High"
    }
  }
  category {
    description = null
    name        = "MP. INFO. 3 Encryption"
    sub_category {
      cloud_configuration_rules = []
      controls                  = []
      description               = null
      host_configuration_rules  = []
      title                     = "Encryption for Classification Level High"
    }
  }
}
