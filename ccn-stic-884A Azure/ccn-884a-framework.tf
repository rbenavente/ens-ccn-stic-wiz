
resource "wiz_security_framework" "ccn_884a" {
  description                        = "The CCN-STIC Guidelines of the National Cryptologic Centre can establish specific  compliance  profiles  for  specific  entities  or  sectors,  which  will include  the list of measures and reinforcements that are applicable in each case, or the criteria for their determination"
  enabled                            = true
  maintain_rule_links_from_framework = null
  name                               = "ENS CCN STIC 884A - Azure "


  category {
    description = "op.acc1  will be applied in category and HIGH level"
    name        = "OP. ACC.1 Identification"
    sub_category {
      cloud_configuration_rules = []
      controls                  = []
      description               = ""
      host_configuration_rules  = []
      title                     = " Identification for Classification Level High"
    }

  }
  category {
    description = "op.acc2  will be applied in category and HIGH level"
    name        = "OP. ACC. 2 Access Requirements"
    sub_category {
      cloud_configuration_rules = [wiz_cloud_configuration_rule.ccn_884a_acc2r2.id,wiz_cloud_configuration_rule.ccn_884a_acc2r4.id]
      controls                  = []
      description               = ""
      host_configuration_rules  = []
      title                     = "Access Requirements for Classification Level High"
    }
  }
   category {
    description = "op.acc3  will be applied in category and HIGH level"
    name        = "OP. ACC. 3 Segregation of Functions and Tasks "
    sub_category {
      cloud_configuration_rules = []
      controls                  = []
      description               = null
      host_configuration_rules  = []
      title                     = "Segregation of Functions and Tasks for Classification Level High"
    }
  }
    
   category {
    description = "op.acc5  will be applied in category and HIGH level"
    name        = "OP. ACC. 5 Authentication Mechanism"
    sub_category {
      cloud_configuration_rules = [wiz_cloud_configuration_rule.ccn_884a_acc5r1.id]
      controls                  = []
      description               = ""
      host_configuration_rules  = []
      title                     = "Authentication Mechanism for Classification Level High"
    }
  } 
   category {
    description = "op.acc6  will be applied in category and HIGH level"
    name        = "OP. ACC. 6 Local Access"
    sub_category {
      cloud_configuration_rules = [wiz_cloud_configuration_rule.ccn_884a_acc6r1.id,wiz_cloud_configuration_rule.ccn_884a_acc6r2.id,wiz_cloud_configuration_rule.ccn_884a_acc6r3.id, wiz_cloud_configuration_rule.ccn_884a_acc6r4.id]
      controls                  = []
      description               = ""
      host_configuration_rules  = []
      title                     = "Local Access (local logon) for Classification Level High"
    }
  } 

  category {
    description = "op.exp8  will be applied in category and HIGH level"
    name        = "OP. EXP.8 User Activity Log"
    sub_category {
      cloud_configuration_rules = [wiz_cloud_configuration_rule.ccn_884a_opexp8r1.id, wiz_cloud_configuration_rule.ccn_884a_opexp8r2.id]
      controls                  = []
      description               = null
      host_configuration_rules  = []
      title                     = "User Activity Log for Classification Level High"
    }    

  }
  category {
    description = "op.exp11  will be applied in category and HIGH level"
    name        = "OP. EXP.11 Protection of Cryptographic Keys"
    sub_category {
      cloud_configuration_rules = [wiz_cloud_configuration_rule.ccn_884a_opexp11r1.id]
      controls                  = []
      description               = null
      host_configuration_rules  = []
      title                     = "Protection of Cryptographic Keys for Classification Level High"
    }    

  }
 
  category {
    description = "op.cont2  will be applied in category and HIGH level"
    name        = "OP.CONT.2 Continuity Plan"
    sub_category {
      cloud_configuration_rules = []
      controls                  = []
      description               = null
      host_configuration_rules  = []
      title                     = "Continuity Plan for Classification Level High"
    }    

  }
    category {
    description = "op.cont3  will be applied in category and HIGH level"
    name        = "OP.CONT.3 Fail over Test"
    sub_category {
      cloud_configuration_rules = []
      controls                  = []
      description               = null
      host_configuration_rules  = []
      title                     = "Failover Test  for Classification Level High"
    }    

  }
    category {
    description = "op.mon1 will be applied in category and HIGH level"
    name        = "OP.MON.1 Intrusion Detection"
    sub_category {
      cloud_configuration_rules = [wiz_cloud_configuration_rule.ccn_884a_opmon1r1.id, wiz_cloud_configuration_rule.ccn_884a_opmon1r2.id]
      controls                  = []
      description               = null
      host_configuration_rules  = []
      title                     = "Intrusion Detection for Classification Level High"
    }    

  }
    category {
    description = "op.mon2 will be applied in category and HIGH level"
    name        = "OP.MON.2 Metric System "
    sub_category {
      cloud_configuration_rules = [wiz_cloud_configuration_rule.ccn_884a_opmon2r1.id, wiz_cloud_configuration_rule.ccn_884a_opmon2r2.id, wiz_cloud_configuration_rule.ccn_884a_opmon2r3.id, wiz_cloud_configuration_rule.ccn_884a_opmon2r4.id, wiz_cloud_configuration_rule.ccn_884a_opmon2r5.id, wiz_cloud_configuration_rule.ccn_884a_opmon2r6.id,wiz_cloud_configuration_rule.ccn_884a_opmon2r7.id,wiz_cloud_configuration_rule.ccn_884a_opmon2r8.id,wiz_cloud_configuration_rule.ccn_884a_opmon2r9.id,wiz_cloud_configuration_rule.ccn_884a_opmon2r10.id]
      controls                  = []
      description               = null
      host_configuration_rules  = []
      title                     = "Metric System  for Classification Level High"
    }    

  }
      category {
    description = "op.mon3 will be applied in category and HIGH level"
    name        = "OP.MON.3 Surveillance"
    sub_category {
      cloud_configuration_rules = [wiz_cloud_configuration_rule.ccn_884a_opmon3r1.id, wiz_cloud_configuration_rule.ccn_884a_opmon3r2.id, wiz_cloud_configuration_rule.ccn_884a_opmon3r3.id, wiz_cloud_configuration_rule.ccn_884a_opmon3r4.id]
      controls                  = []
      description               = null
      host_configuration_rules  = []
      title                     = "Surveillance for Classification Level High"
    }    

  }
    category {
    description = "mp.com1 will be applied in category and HIGH level"
    name        = "OP.COM.1 Secure Perimeter "
    sub_category {
      cloud_configuration_rules = [wiz_cloud_configuration_rule.ccn_884a_mpcom1r1.id, wiz_cloud_configuration_rule.ccn_884a_mpcom1r2.id, wiz_cloud_configuration_rule.ccn_884a_mpcom1r3.id]
      controls                  = []
      description               = null
      host_configuration_rules  = []
      title                     = "Secure Perimeter for Classification Level High"
    }    

  }
    category {
    description = "mp.com2 will be applied in category and HIGH level"
    name        = "OP.COM.2 Protection of Confidentiality"
    sub_category {
      cloud_configuration_rules = [wiz_cloud_configuration_rule.ccn_884a_mpcom2r1.id]
      controls                  = []
      description               = null
      host_configuration_rules  = []
      title                     = "Protection of Confidentiality for Classification Level High"
    }    

  }

    category {
    description = "mp.com3 will be applied in category and HIGH level"
    name        = "OP.COM.3 Protection of Authenticity and Integrity"
    sub_category {
      cloud_configuration_rules = [wiz_cloud_configuration_rule.ccn_884a_opmon3r1.id, wiz_cloud_configuration_rule.ccn_884a_opmon3r2.id, wiz_cloud_configuration_rule.ccn_884a_opmon3r3.id, wiz_cloud_configuration_rule.ccn_884a_opmon3r4.id,wiz_cloud_configuration_rule.ccn_884a_acc6r1.id,wiz_cloud_configuration_rule.ccn_884a_acc6r2.id,wiz_cloud_configuration_rule.ccn_884a_acc6r3.id, wiz_cloud_configuration_rule.ccn_884a_acc6r4.id,wiz_cloud_configuration_rule.ccn_884a_mps4r1.id]
      controls                  = []
      description               = null
      host_configuration_rules  = []
      title                     = "Protection of Authenticity and Integrity for Classification Level High"
    }    

  }

    category {
    description = "mp.com4 will be applied in category and HIGH level"
    name        = "OP.COM.4 Network Segregation"
    sub_category {
      cloud_configuration_rules = []
      controls                  = []
      description               = null
      host_configuration_rules  = []
      title                     = "Network Segregation for Classification Level High"
    }    

  }

    category {
    description = "mp.info2 will be applied in category and HIGH level"
    name        = "MP. INFO. 2 Qualification of Information"
    sub_category {
      cloud_configuration_rules = [wiz_cloud_configuration_rule.ccn_884a_mpinfo2r1.id]
      controls                  = []
      description               = null
      host_configuration_rules  = []
      title                     = "Qualification of Information for Classification Level High"
    }
  }

    category {
    description = "mp.info9 will be applied in category and HIGH level"
    name        = "MP. INFO. 9 Backup"
    sub_category {
      cloud_configuration_rules = [wiz_cloud_configuration_rule.ccn_884a_mpinfo9r1.id, wiz_cloud_configuration_rule.ccn_884a_mpinfo9r2.id, wiz_cloud_configuration_rule.ccn_884a_mpinfo9r3.id]
      controls                  = []
      description               = null
      host_configuration_rules  = []
      title                     = "Backup for Classification Level High"
    }
  }


    category {
    description = "mp.s4 will be applied in category and HIGH level"
    name        = "MP. S.4 Protection against Denial of Service"
    sub_category {
      cloud_configuration_rules = [wiz_cloud_configuration_rule.ccn_884a_mps4r1.id]
      controls                  = []
      description               = null
      host_configuration_rules  = []
      title                     = "Protection against Denial of Service for Classification Level High"
    }
  }
  }



