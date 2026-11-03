output "private_ip_address" {
  description = "IP privada del host para que el edge protegido publique /b89-respond/ después de la prueba de sesión."
  value       = azurerm_network_interface.b89-respond.private_ip_address
}

output "network_security_group_id" {
  value = azurerm_network_security_group.b89-respond.id
}

output "route_table_id" {
  description = "UDR propia de la subnet dedicada, con 0/0 forzado al firewall."
  value       = azurerm_route_table.b89-respond.id
}

output "managed_disk_id" {
  description = "Disco independiente con prevent_destroy para las definiciones/datos de B89 Respond."
  value       = azurerm_managed_disk.b89_respond_data.id
}

output "runtime_status" {
  description = "Cloud-init instala y arranca Compose en el primer inicio; este valor no afirma que el host desplegado haya pasado sus health checks."
  value       = "cloud_init_start_configured_health_unverified"
}
