terraform {
  required_providers {
    wiz = {
      version = " ~> 1.14"
      source = "tf.app.wiz.io/wizsec/wiz"
    }
  }
}

provider "wiz" {
  client_id = "ixxxxx
  secret = "xxxxx”
}
