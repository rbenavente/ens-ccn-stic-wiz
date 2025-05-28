Este repositorio incluye los controles de seguridad que mapean con las guias de bastionado STIC del CCN CERT.
Estos controles crearán el framework personalizado en la consola de Wiz con nombre ENS CCN-STIC-xxx. 
Para actualizar estos controles se utiliza Terraform y a continuación se indican los pasos a realizar:


**Pre-requisito**

Asegúrate de tener instalado Terraform: terraform -v

**1. Clonar el Repositorio de GitHub**
 
  Abre una terminal y ejecuta:
 
  git clone https://github.com/rbenavente/ens-ccn-stic-wiz.git
  
  cd ens-ccn-stic-wiz

Ve a la carpeta del marco que quieras cargar, por ejemplo para  los controles de Azure: 

  cd ens-ccn-stic-wiz 


**2. Crear una Service Account en Wiz**

Para esto necesitas tener permisos de administrador en tu cuenta de Wiz. Los pasos típicos:

Opción: Desde la UI de Wiz

	1.Inicia sesión en el portal de Wiz: https://app.wiz.io
 
	2.Ve a Settings > Service Accounts
 
	3.Haz clic en Create Service Account
 
	4.Asigna un nombre, y selecciona los permisos necesarios:
	      Type: Custom Integration (GraphQL API)
	      En el API Scope seleccionar:
		      Controls: todos los permisos
		      Cloud Configuration:  todos los permisos
		      Security Frameworks: todos los permisos
    
	5.Copia el Client ID y Client Secret — los usarás con Terraform


**3. Configurar Credenciales de Wiz en Terraform**

Terraform usará un provider específico para Wiz. Asegúrate de que en el repo tienes un archivo como main.tf y actualiza etos valores con la cuenta de servicio creada anteriormente: 

    provider "wiz" {
      client_id = "ixxxxx
      secret = "xxxxx”
    }


**4. Ejecutar Terraform**

Ejecuta estos comandos de terraform para cargar las politicas y marco normativo:

    terraform init
    terraform plan
    terraform apply


**5. Comprobar en WIZ que el marco se ha cargado**

Ir a la consola de WIZ Reports  > Compliance Posture y buscar el marco recien creado via terraform. 


**OPCIONAL 
**
Si por alguna razon se desea eliminar el marco normativo cargados solo es necesario ejecutar este comando: 
terraform destroy
