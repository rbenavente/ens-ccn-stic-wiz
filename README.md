Para ejecutar los pantillas de TF es necesario configurar el provider y las credenciales. A modo de ejemplo


terraform {
  required_providers {
    wiz = {
      version = " ~> 1.7"
      source = "tf.app.wiz.io/wizsec/wiz"
    }
  }
}

provider "wiz" {
  client_id = "your client id"
  secret = "you secret"
}


Mas información sobre el uso del provider de wiz en https://docs.wiz.io/wiz-docs/docs/wiz-terraform-provider


Para desplegar los controles: 
terraform init
terraform plan
terraform apply 


Para eliminarlos:
terraform destroy
