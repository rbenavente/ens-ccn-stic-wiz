resource "wiz_security_framework" "ens_ccn_stic_887a_framework" {
  name        = "ENS CCN STIC 887A - AWS"
  description = "Security Framework based on ENS CCN STIC 887A. The CCN-STIC Guidelines of the National Cryptologic Centre can establish specific  compliance  profiles  for  specific  entities  or  sectors,  which  will include  the list of measures and reinforcements that are applicable in each case, or the criteria for their determination"
  enabled     = true # Set to true to enable the framework

  
  # --- Categories and Subcategories of the framework ---

  category {
    name        = "op.pl.2 - Security architecture"
    description = "It is recommended that the user entity rely on the AWS Well-Architected Framework"

    sub_category {
      title                     = "Security architecture for Category: Basic, Medium, High. Level: N/A"
      description               = null
      controls                  = [] 
      host_configuration_rules  = [] 
    }
  }
   category {
    name        = "op.pl.4 - Sizing / Capacity Management"
    description = "OP PL- Planning"
    sub_category {
      title                     = "Sizing / Capacity Management for Category: Basic. Level: High"
      description               = null
      cloud_configuration_rules = []
      controls                  = []
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R1 - Continuous improvement of capacity management for Category: Medium, High. Level: High"
      description               = null
      cloud_configuration_rules = []
      controls                  = []
      host_configuration_rules  = []
    }
  } 

  category {
    name        = "OP. ACC.1 - Identification"
    description = "OP ACC- Access Control"

    sub_category {
      title                     = "Identification for Category: Basic. Level: High"
      description               = null
      cloud_configuration_rules = [wiz_cloud_configuration_rule.op-acc-1-1.id,wiz_cloud_configuration_rule.op-acc-1-2.id]
      controls                  = []
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R1 - Advanced identification for Category: Medium, High. Level: High"
      description               = null
      cloud_configuration_rules = []
      controls                  = []
      host_configuration_rules  = []
    }
  }
 category {
    name        = "OP. ACC.2 - Access Requirements"
    description = "OP ACC- Access Control"

    sub_category {
      title                     = "op.acc.2- Access requirements for Category: Basic, Medium, High. Level: Medium"
      description               = null
      cloud_configuration_rules = [wiz_cloud_configuration_rule.op-acc-2-1.id]
      controls                  = []
      host_configuration_rules  = []
    }
 }
  category {
    name        = "OP.ACC.3- Segregation of Functions and Tasks"
    description = "OP ACC- Access Control"

    sub_category {
      title                     = "Segregation of functions and tasks for Category: Medium, High. Level: HighPrivilege"
      description               = null
      cloud_configuration_rules = [wiz_cloud_configuration_rule.op-acc-3-1.id]
      controls                  = []
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R1- Strict segregation for Category: High. Level: High"
      description               = null
      cloud_configuration_rules = [wiz_cloud_configuration_rule.op-acc-3-r1-1.id]
      controls                  = []
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R2 - Audit privileges for Category: High. Level: High"
      description               = null
      cloud_configuration_rules = []
      controls                  = []
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R3 - Access to security information for Category: High. Level: High"
      description               = null
      cloud_configuration_rules = []
      controls                  = []
      host_configuration_rules  = []
    }
  }
   category {
    name        = "OP. ACC.4- Access Rights Management Process"
    description = "OP ACC- Access Control"

    sub_category {
      title                     = "Access rights management process for Category: Basic, Medium, High. Level: High"
      description               = null
      cloud_configuration_rules = [wiz_cloud_configuration_rule.op-acc-4-1.id,wiz_cloud_configuration_rule.op-acc-4-2.id,wiz_cloud_configuration_rule.op-acc-4-3.id,wiz_cloud_configuration_rule.op-acc-4-4.id,wiz_cloud_configuration_rule.op-acc-4-5.id,wiz_cloud_configuration_rule.op-acc-4-6.id,wiz_cloud_configuration_rule.op-acc-4-7.id,wiz_cloud_configuration_rule.op-acc-4-8.id,wiz_cloud_configuration_rule.op-acc-4-9.id,wiz_cloud_configuration_rule.op-acc-4-10.id,wiz_cloud_configuration_rule.op-acc-4-11.id,wiz_cloud_configuration_rule.op-acc-4-12.id,wiz_cloud_configuration_rule.op-acc-4-13.id]
      controls                  = []
      host_configuration_rules  = []
    }
   }
  category {
    name        = "OP. ACC.6- Authentication Mechanism"
    description = "OP ACC- Access Control"
    sub_category {
      title                     = "Authentication mechanism for Category: Basic, Medium, High. Level: High"
      description               = null
      cloud_configuration_rules = [wiz_cloud_configuration_rule.op-acc-6-1.id,wiz_cloud_configuration_rule.op-acc-6-2.id,wiz_cloud_configuration_rule.op-acc-6-3.id,wiz_cloud_configuration_rule.op-acc-6-4.id]
      controls                  = []
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R1 - Passswords for Category: Basic, Medium, High. Level: High"
      description               = null
      cloud_configuration_rules = [wiz_cloud_configuration_rule.op-acc-6-r1-1.id,wiz_cloud_configuration_rule.op-acc-6-r1-2.id,wiz_cloud_configuration_rule.op-acc-6-r1-3.id,wiz_cloud_configuration_rule.op-acc-6-r1-4.id,wiz_cloud_configuration_rule.op-acc-6-r1-5.id,wiz_cloud_configuration_rule.op-acc-6-r1-6.id,wiz_cloud_configuration_rule.op-acc-6-r1-7.id]
      controls                  = []
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R2 - Password plus another authentication factor for Category: Basic, Medium, High. Level: High"
      description               = null
      cloud_configuration_rules = [wiz_cloud_configuration_rule.op-acc-6-r2-1.id,wiz_cloud_configuration_rule.op-acc-6-r2-2.id,wiz_cloud_configuration_rule.op-acc-6-r2-4.id]
      controls                  = [wiz_control.op-acc-6-r2-3.id]
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R3 - Certificates for Category: Basic, Medium, High. Level: High"
      description               = null
      cloud_configuration_rules = []
      controls                  = []
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R4 - Certificates on a physical device for Category: Basic, Medium, High. Level: High"
      description               = null
      cloud_configuration_rules = [wiz_cloud_configuration_rule.op-acc-6-r4-1.id]
      controls                  = []
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R5 - Logging for Category: Basic, Medium, High. Level: High"
      description               = null
      cloud_configuration_rules = [wiz_cloud_configuration_rule.op-acc-6-r5-1.id,wiz_cloud_configuration_rule.op-acc-6-r5-2.id]
      controls                  = []
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R7-  Suspension due to inactivity for Category: High. Level: High"
      description               = null
      cloud_configuration_rules = [wiz_cloud_configuration_rule.op-acc-6-r7-1.id,wiz_cloud_configuration_rule.op-acc-6-r7-2.id,wiz_cloud_configuration_rule.op-acc-6-r7-3.id]
      controls                  = []
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R8- Two-factor authentication for access from or through uncontrolled zones for Category: Basic, Medium, High. Level: High"
      description               = null
      cloud_configuration_rules = []
      controls                  = []
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R9- Remote access for Category: Basic, Medium, High. Level: High"
      description               = null
      cloud_configuration_rules = []
      controls                  = []
      host_configuration_rules  = []
    }
  } 

  category {
    name        = "OP. EXP.1 - Inventory of Assets"
    description = "Operational Exploitation/Maintenance controls."

    sub_category {
      title                     = "Inventory of assets for Category: Basic, Medium, High. Level: High"
      description               = null
      cloud_configuration_rules = []
      controls                  = [wiz_control.op-exp-1-1.id]
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R1 - Inventory tagging for Category: Basic, Medium, High. Level: High"
      description               = null
      cloud_configuration_rules = []
      controls                  = []
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R2 - Periodic asset identification for Category: Basic, Medium, High. Level: High"
      description               = null
      cloud_configuration_rules = []
      controls                  = []
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R3 - Critical asset identification for Category: Basic, Medium, High. Level: High"
      description               = null
      cloud_configuration_rules = []
      controls                  = []
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R4 - SBOM for Category: Basic, Medium, High. Level: High"
      description               = null
      cloud_configuration_rules = []
      controls                  = []
      host_configuration_rules  = []
    }
  }
 
  category {
    name        = "OP. EXP.3 - Security Settings Management"
    description = "Operational Exploitation/Maintenance controls."
 
    sub_category {
      title                     = "Security settings Management for Category: Basic, Medium, High. Level: High"
      description               = null
      cloud_configuration_rules = []
      controls                  = []
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R2 - Configuration responsibility for Category: High. Level: High"
      description               = null
      cloud_configuration_rules = []
      controls                  = []
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R3 - Backups for Category: High. Level: High"
      description               = null
      cloud_configuration_rules = []
      controls                  = []
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R4 - Configuration enforcement for Category: High. Level: High"
      description               = null
      cloud_configuration_rules = [wiz_cloud_configuration_rule.op-exp-3-r4-1.id,wiz_cloud_configuration_rule.op-exp-3-r4-2.id]
      controls                  = []
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R5 - Monitoring of configuration security posture for Category: High. Level: High" 
      description               = null
      cloud_configuration_rules = []
      controls                  = []
      host_configuration_rules  = []
    }
  }
    category {
    name        = "OP. EXP.4 - Maintenance and Security Updates"
    description = "Operational Exploitation/Maintenance controls."
 
    sub_category {
      title                     = "Maintenance and security updates for Category: Basic, Medium, High. Level: Basic"
      description               = null
      cloud_configuration_rules = [wiz_cloud_configuration_rule.op-exp-3-r4-2.id,wiz_cloud_configuration_rule.op-exp-4-2.id]
      controls                  = []
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R1 - Pre-production testing for Category:  Medium, High. Level: Basic"
      description               = null
      cloud_configuration_rules = []
      controls                  = []
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R2 - Failure prevention for Category: High. Level: Basic"
      description               = null
      cloud_configuration_rules = [wiz_cloud_configuration_rule.op-acc-4-13.id]
      controls                  = []
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R4 - Continuous monitoring for Category: High. Level: Basic"
      description               = null
      cloud_configuration_rules = []
      controls                  = []
      host_configuration_rules  = []
    }
    }

  category {
    name        = "OP. EXP.5 - Change Management"
    description = "Operational Exploitation/Maintenance controls."
  
    sub_category {
      title                     = "Change management for Category:  Medium, High. Level: N/A"
      description               = null
      cloud_configuration_rules = []
      controls                  = []
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R1 - Failure prevention for Category:  High. Level: N/A"
      description               = null
      cloud_configuration_rules = []
      controls                  = []
      host_configuration_rules  = []
    }
  }
  category {
    name        = "OP. EXP.6 - Malware Protection "
    description = "Operational Exploitation/Maintenance controls."
    
    sub_category {
      title                     = "Protection against malware for Category: Basic, Medium, High. Level: Basic"
      description               = null
      cloud_configuration_rules = [wiz_cloud_configuration_rule.op-exp-6-1.id]
      controls                  = []
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R3 - Whitelist for Category: High. Level: Basic"
      description               = null
      cloud_configuration_rules = []
      controls                  = []
      host_configuration_rules  = []
    }
  }
   category {
    name        = "OP. EXP.7 - Incident Management "
    description = "Operational Exploitation/Maintenance controls."
 
    sub_category {
      title                     = "Incident Management for Category: Basic, Medium, High. Level: Basic"
      description               = null
      cloud_configuration_rules = [wiz_cloud_configuration_rule.op-exp-7-1.id,wiz_cloud_configuration_rule.op-exp-7-2.id,wiz_cloud_configuration_rule.op-exp-7-3.id,wiz_cloud_configuration_rule.op-exp-7-4.id,wiz_cloud_configuration_rule.op-exp-7-5.id,wiz_cloud_configuration_rule.op-exp-7-6.id,wiz_cloud_configuration_rule.op-exp-7-7.id,wiz_cloud_configuration_rule.op-exp-7-8.id,wiz_cloud_configuration_rule.op-exp-7-9.id,wiz_cloud_configuration_rule.op-exp-7-10.id,wiz_cloud_configuration_rule.op-exp-7-12.id,wiz_cloud_configuration_rule.op-exp-7-13.id,wiz_cloud_configuration_rule.op-exp-7-14.id]
      controls                  = [wiz_control.op-exp-7-11.id]
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R4 - Automated Prevention and Response for Category: High. Level: Basic"
      description               = null
      cloud_configuration_rules = []
      controls                  = []
      host_configuration_rules  = []
    }
   }
   category {
    name        = "OP. EXP.8 - User Activity Log "
    description = "Operational Exploitation/Maintenance controls."
  
    sub_category {
      title                     = "User activity log for Category: Basic, Medium, High. Level: Medium" 
      description               = null
      cloud_configuration_rules = [wiz_cloud_configuration_rule.op-exp-8-1.id,wiz_cloud_configuration_rule.op-exp-8-2.id,wiz_cloud_configuration_rule.op-exp-8-3.id,wiz_cloud_configuration_rule.op-exp-8-4.id]
      controls                  = []
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R1 - Log review for Category: Medium, High. Level: Medium"
      description               = null
      cloud_configuration_rules = [wiz_cloud_configuration_rule.op-exp-8-r1-16.id,wiz_cloud_configuration_rule.op-exp-8-r1-17.id]
      controls                  = [wiz_control.op-exp-8-r1-1.id,wiz_control.op-exp-8-r1-2.id,wiz_control.op-exp-8-r1-3.id,wiz_control.op-exp-8-r1-4.id,wiz_control.op-exp-8-r1-5.id,wiz_control.op-exp-8-r1-6.id,wiz_control.op-exp-8-r1-7.id,wiz_control.op-exp-8-r1-8.id,wiz_control.op-exp-8-r1-9.id,wiz_control.op-exp-8-r1-10.id,wiz_control.op-exp-8-r1-11.id,wiz_control.op-exp-8-r1-12.id,wiz_control.op-exp-8-r1-13.id,wiz_control.op-exp-8-r1-14.id,wiz_control.op-exp-8-r1-15.id,wiz_control.op-exp-8-r1-18.id,wiz_control.op-exp-8-r1-19.id]
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R2 - Log retetion for Category: Medium, High. Level: Medium"
      description               = null
      cloud_configuration_rules = []
      controls                  = []
      host_configuration_rules  = []
    }

    sub_category {
      title                     = "R4 - Access Control for Category: Medium, High. Level: Medium"
      description               = null
      cloud_configuration_rules = [wiz_cloud_configuration_rule.op-exp-8-r4-1.id,wiz_cloud_configuration_rule.op-exp-8-r4-3.id,wiz_cloud_configuration_rule.op-exp-8-r4-4.id,wiz_cloud_configuration_rule.op-exp-8-r4-5.id]
      controls                  = [wiz_control.op-exp-8-r4-2.id]
      host_configuration_rules  = []
    }
   }
   category {
    name        = "OP. EXP.9 - Incident Management Log "
    description = "Operational Exploitation/Maintenance controls."

    sub_category {
      title                     = "Incident Management Log for Category: Basic, Medium, High. Level: Basic"
      description               = null
      cloud_configuration_rules = []
      controls                  = []
      host_configuration_rules  = []
    }
   }
  category {
    name        = "OP. EXP.10 - Cryptographic Keys Protection"
    description = "Operational Exploitation/Maintenance controls."
 
    sub_category {
      title                     = "Protection of cryptographic keys for Category: Basic, Medium, High. Level: High"
      description               = null
      cloud_configuration_rules = [wiz_cloud_configuration_rule.op-exp-10-2.id,wiz_cloud_configuration_rule.op-exp-10-3.id,wiz_cloud_configuration_rule.op-exp-10-4.id,wiz_cloud_configuration_rule.op-exp-10-5.id,wiz_cloud_configuration_rule.op-exp-10-6.id,wiz_cloud_configuration_rule.op-exp-10-7.id,wiz_cloud_configuration_rule.op-exp-10-8.id,wiz_cloud_configuration_rule.op-exp-10-9.id]
      controls                  = [wiz_control.op-exp-10-1.id]
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R1- Only approved algorithms for Category: Medium, High. Level: High"
      description               = null
      cloud_configuration_rules = []
      controls                  = []
      host_configuration_rules  = []
    }
  } 


  category {
    name        = "OP. EXT.1  - Contracting and Services Level Agreements"
    description = "Operational External Interfaces controls."

    sub_category {
      title                     = "Contracting and services level agreements for Category: Basic, Medium, High. Level: High"
      description               = null
      cloud_configuration_rules = []
      controls                  = []
      host_configuration_rules  = []
    }
  }
 category {
    name        = "OP. EXT.2  - Daily Management"
    description = "Operational External Interfaces controls."

    sub_category {
      title                     = "Daily management for Category: Basic, Medium, High. Level: High"
      description               = null
      cloud_configuration_rules = [wiz_cloud_configuration_rule.op-acc-3-r1-1.id]
      controls                  = []
      host_configuration_rules  = []
    }
  } 

  category {
    name        = "OP. CONT.2 - Continuity Plan"
    description = "Operational Continuity controls."

    sub_category {
      title                     = "Continuity Plan for Category: High. Level: High"
      description               = null
      cloud_configuration_rules = []
      controls                  = []
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R2 - Integrity verification for Category: High. Level: High"
      description               = null
      cloud_configuration_rules = []
      controls                  = []
      host_configuration_rules  = []
    }
  }
   category {
    name        = "OP. CONT.3 - Periodic Testing"
    description = "Operational Continuity controls."
 
    sub_category {
      title                     = "Periodic Testing for Category: High. Level: High"
      description               = null
      cloud_configuration_rules = []
      controls                  = []
      host_configuration_rules  = []
    }
   }
     category {
    name        = "OP. CONT.4 - Alternative Means"
    description = "Operational Continuity controls."
  
    sub_category {
      title                     = "Alternative Means for Category: High. Level: High"
      description               = null
      cloud_configuration_rules = []
      controls                  = []
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R1 - Automation of the transition to alternative media for Category: High. Level: High"
      description               = null
      cloud_configuration_rules = []
      controls                  = []
      host_configuration_rules  = []
    }
  } 

  category {
    name        = "OP. MON.1 - Intrusion Detection"
    description = "Operational Monitoring controls."

    sub_category {
      title                     = "Intrusion detection for Category: Basic, Medium, High. Level: Basic"
      description               = null
      cloud_configuration_rules = [wiz_cloud_configuration_rule.op-mon-1-1.id,wiz_cloud_configuration_rule.op-mon-1-2.id]
      controls                  = []
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R3 - Default actions for Category: High. Level: Basic "
      description               = null
      cloud_configuration_rules = []
      controls                  = []
      host_configuration_rules  = []
    }
  }
    category {
    name        = "OP. MON.2 - Metric System"
    description = "Operational Monitoring controls."

    sub_category {
      title                     = "Metric system for Category: Basic, Medium, High. Level: High"
      description               = null
      cloud_configuration_rules = []
      controls                  = [wiz_control.op-exp-7-11.id]
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R2 - Efficiency of the security management system for Category: High. Level: High"
      description               = null
      cloud_configuration_rules = []
      controls                  = []
      host_configuration_rules  = []
    }
    }
  category {
    name        = "OP. MON.3 - Surveillance"
    description = "Operational Monitoring controls."
 
    sub_category {
      title                     = "Surveillance for Category: Basic, Medium, High. Level: High"
      description               = null
      cloud_configuration_rules = [wiz_cloud_configuration_rule.op-mon-3-1.id]
      controls                  = []
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R1 - Event correlation for Category: Medium, High. Level: High"
      description               = null
      cloud_configuration_rules = [wiz_cloud_configuration_rule.op-exp-6-1.id]
      controls                  = [wiz_control.op-exp-7-11.id]
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R2 - Dynamic analysis for Category: Medium, High. Level: High"
      description               =null
      cloud_configuration_rules = [wiz_cloud_configuration_rule.op-mon-3-r2-1.id]
      controls                  = [wiz_control.op-exp-7-11.id]
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R3 - Advanced cyber threats for Category: High. Level: High"
      description               = null
      cloud_configuration_rules = [wiz_cloud_configuration_rule.op-exp-6-1.id]
      controls                  = []
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R5 - Data mining for Category: High. Level: High"
      description               = null
      cloud_configuration_rules = [wiz_cloud_configuration_rule.op-exp-6-1.id]
      controls                  = []
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R6 - Security inspections for Category: High. Level: High"
      description               =null
      cloud_configuration_rules = []
      controls                  = []
      host_configuration_rules  = []
    }
  } 

  category {
    name        = "MP. COM.1 - Secure Perimeter"
    description = "Measures of Protection for Communication."

    sub_category {
      title                     = "Secure perimeter for Category: Basic, Medium, High. Level: High"
      description               = null
      cloud_configuration_rules = [wiz_cloud_configuration_rule.mp-com-1-1.id,wiz_cloud_configuration_rule.mp-com-1-2.id,wiz_cloud_configuration_rule.mp-com-1-3.id,wiz_cloud_configuration_rule.mp-com-1-4.id,wiz_cloud_configuration_rule.mp-com-1-5.id]
      controls                  = []
      host_configuration_rules  = []
    }
  }
    category {
    name        = "MP. COM.2 - Protection of Confidentiality"
    description = "Measures of Protection for Communication."
  
    sub_category {
      title                     = "Protection of confidentiality for Category: Basic, Medium, High. Level: High"
      description               = null
      cloud_configuration_rules = [wiz_cloud_configuration_rule.mp-com-2-1.id]
      controls                  = []
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R1 - Approved algorithms and parameters for Category: Medium, High. Level: High"
      description               = null
      cloud_configuration_rules = []
      controls                  = []
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R2 - Hardware devices for Category: High. Level: High"
      description               = null
      cloud_configuration_rules = []
      controls                  = []
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R3 - Certified products for Category: High. Level: High"
      description               = null
      cloud_configuration_rules = []
      controls                  = []
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R4 - Encryption tools for Category: High. Level: High"
      description               = null
      cloud_configuration_rules = []
      controls                  = []
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R5 - Encryption of highly sensitive information for Category: High. Level: High"
      description               =  null
      cloud_configuration_rules = []
      controls                  = [wiz_control.mp-com-2-r5-1.id]
      host_configuration_rules  = []
    }
    }
  category {
    name        = "MP. COM.3 - Protection of Authenticity and Integrity"
    description = "Measures of Protection for Communication."
   
    sub_category {
      title                     = "Protection of authenticity and integrity for Category: Basic, Medium, High. Level: Basic"
      description               = null
      cloud_configuration_rules = [wiz_cloud_configuration_rule.mp-com-3-1.id,wiz_cloud_configuration_rule.mp-com-3-2.id,wiz_cloud_configuration_rule.mp-com-3-3.id]
      controls                  = []
      host_configuration_rules  = []
    }
  }

  category {
    name        = "MP. COM.4 - Network Segregation"
    description = "Measues of Protection for Communication."
   
    sub_category {
      title                     = "Network Segregation for Category: Medium, High. Level: Medium"
      description               = null
      cloud_configuration_rules = [wiz_cloud_configuration_rule.mp-com-4-1.id,wiz_cloud_configuration_rule.mp-com-4-2.id]
      controls                  = []
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R1- Basic logical segmentation for Category: Medium, High. Level: Medium"
      description               = null

      cloud_configuration_rules = []
      controls                  = []
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R2 - Advanced logical segmentation for Category: Medium, High. Level: Medium"
      description               = null
      cloud_configuration_rules = []
      controls                  = []
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R3 - Physical segmentation for Category: Medium, High. Level: Medium"
      description               = null
      cloud_configuration_rules = []
      controls                  = []
      host_configuration_rules  = []
    }
  } 

  category {
    name        = "MP. SI.2 - Cryptography"
    description = "Measures of Protection for System Integrity."

    sub_category {
      title                     = "Cryptography for Category: Medium, High. Level: High"
      description               = null
      cloud_configuration_rules = [wiz_cloud_configuration_rule.mp-si-2-1.id,wiz_cloud_configuration_rule.mp-si-2-2.id,wiz_cloud_configuration_rule.mp-si-2-3.id,wiz_cloud_configuration_rule.mp-si-2-4.id,wiz_cloud_configuration_rule.mp-si-2-5.id,wiz_cloud_configuration_rule.mp-si-2-6.id,wiz_cloud_configuration_rule.mp-si-2-7.id]
      controls                  = []
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R1 - Certified products for Category: High. Level: High"
      description               = null
      cloud_configuration_rules = [wiz_cloud_configuration_rule.mp-sw-2-r1-1.id]
      controls                  = []
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R2 - Backups for Category: High. Level: High"
      description               = null
      cloud_configuration_rules = []
      controls                  = []
      host_configuration_rules  = []
    }
  } 

  category {
    name        = "MP. SW.2 - Development, Acceptance and Commissioningt"
    description = "Measures of Protection for Software and Development."

    sub_category {
      title                     = "R1 - Testing for Category: Medium, High. Level: Medium"
      description               = null
      cloud_configuration_rules = []
      controls                  = []
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R2 - Source code inspection for Category: Medium, High. Level: Medium"
      description               = null
      cloud_configuration_rules = []
      controls                  = []
      host_configuration_rules  = []
    }
  } 

  category {
    name        = "M. INFO.6 - Backup"
    description = "Measures of Protection for Information."

    sub_category {
      title                     = "mp.info.6 - Backup for Category:Basic, Medium, High. Level: High"
      description               = null
      cloud_configuration_rules = [wiz_cloud_configuration_rule.mp-info-6-1.id,wiz_cloud_configuration_rule.mp-info-6-2.id,wiz_cloud_configuration_rule.mp-info-6-3.id,wiz_cloud_configuration_rule.mp-info-6-4.id,wiz_cloud_configuration_rule.mp-info-6-5.id]
      controls                  = []
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R1 - Recovery testing for Category: Medium, High. Level: High"
      description               = null
      cloud_configuration_rules = []
      controls                  = []
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R2 - Backup protection for Category: High. Level: High"
      description               = null
      cloud_configuration_rules = []
      controls                  = []
      host_configuration_rules  = []
    }
  } 

  category {
    name        = "MP. S.1 - Email Protection "
    description = "Measures of Protection for Services."

    sub_category {
      title                     = "mp.s.1 - Email Protection for Category: Basic, Medium, High. Level: High"
      description               = null
      cloud_configuration_rules = []
      controls                  = []
      host_configuration_rules  = []
    }
  }
    category {
    name        = "MP. S.2 - Protection of Web services and Applications "
    description = "Measures of Protection for Services."

    sub_category {
      title                     = "Protection of web services and applications for Category: Basic, Medium, High. Level: Basic"
      description               = null
      cloud_configuration_rules = [wiz_cloud_configuration_rule.mp-s-2-1.id,wiz_cloud_configuration_rule.mp-s-2-2.id]
      controls                  = [wiz_control.mp-s-2-3.id]
      host_configuration_rules  = []
    }
    }
  category {
    name        = "MP. S.4 - Protection against Denial of Service "
    description = "Measures of Protection for Services."
 
    sub_category {
      title                     = "Protection against denial of service for Category: Medium, High. Level: High"
      description               = null
      cloud_configuration_rules = [wiz_cloud_configuration_rule.mp-s-4-1.id]
      controls                  = []
      host_configuration_rules  = []
    }
    sub_category {
      title                     = "R1 - Detection and response for Category: High. Level: High"
      description               = null
      cloud_configuration_rules = [wiz_cloud_configuration_rule.mp-s-4-r1-1.id]
      controls                  = []
      host_configuration_rules  = []
    }
  } 

} 
