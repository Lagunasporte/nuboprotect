# 🚀 NuboLink API

> **VPN API Server** con integración WireGuard + Mikrotik para la aplicación iOS NuboProtect

[![Node.js](https://img.shields.io/badge/Node.js-16+-green.svg)](https://nodejs.org/)
[![Express](https://img.shields.io/badge/Express-4.18+-blue.svg)](https://expressjs.com/)
[![SQLite](https://img.shields.io/badge/SQLite-3+-lightgrey.svg)](https://sqlite.org/)
[![WireGuard](https://img.shields.io/badge/WireGuard-Ready-orange.svg)](https://www.wireguard.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## 📋 Descripción

**NuboLink API** es el backend completo para la aplicación VPN iOS **NuboProtect**. Proporciona una API REST segura para gestionar:

- ✅ **Autenticación JWT** de usuarios
- ✅ **Configuración WireGuard** automática
- ✅ **Integración SSH** con routers Mikrotik
- ✅ **DNS seguro** con filtrado de contenido
- ✅ **Gestión multi-país** de servidores VPN
- ✅ **Estadísticas** de uso en tiempo real

## 🏗️ Arquitectura

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   iOS App       │◄──►│   NuboLink API   │◄──►│  Mikrotik SSH   │
│  (NuboProtect)  │    │  (Express.js)    │    │  (WireGuard)    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │
                         ┌──────▼──────┐
                         │   SQLite    │
                         │  Database   │
                         └─────────────┘
```

## 🚀 Inicio Rápido

### **1. Clonar Repositorio**
```bash
git clone https://github.com/yourusername/nubolink-api.git
cd nubolink-api
```

### **2. Instalar Dependencias**
```bash
npm install
```

### **3. Configurar Variables de Entorno**
```bash
cp .env.example .env
# Editar .env con tus configuraciones
```

### **4. Inicializar Base de Datos**
```bash
npm run setup
```

### **5. Iniciar Servidor**
```bash
# Desarrollo
npm run dev

# Producción
npm start
```

## ⚙️ Configuración

### **Variables de Entorno (.env)**

```env
# Servidor
PORT=3001
NODE_ENV=development

# JWT
JWT_SECRET=your-super-secret-jwt-key-change-this

# Base de Datos
DATABASE_PATH=./database/nubolink.sqlite

# Mikrotik Servers
MIKROTIK_ES_HOST=146.66.254.253
MIKROTIK_ES_USER=api-user
MIKROTIK_ES_PASS=secure-password

MIKROTIK_US_HOST=146.66.254.254
MIKROTIK_US_USER=api-user
MIKROTIK_US_PASS=secure-password

# DNS Servers
DNS_PRIMARY=146.66.254.253
DNS_SECONDARY=146.66.254.252

# Logging
LOG_LEVEL=info
LOG_FILE=./logs/api.log
```

## 📡 API Endpoints

### **🔐 Autenticación**
```http
POST /api/auth/register     # Registrar usuario
POST /api/auth/login        # Iniciar sesión
GET  /api/auth/profile      # Perfil del usuario
```

### **🌐 VPN**
```http
GET    /api/vpn/countries        # Lista de países disponibles
POST   /api/vpn/connect         # Conectar a país específico
DELETE /api/vpn/disconnect      # Desconectar VPN
GET    /api/vpn/status          # Estado de conexión
GET    /api/vpn/config          # Configuración WireGuard
```

### **🛡️ DNS**
```http
GET  /api/dns/servers       # Servidores DNS disponibles
POST /api/dns/enable        # Activar DNS seguro
POST /api/dns/disable       # Desactivar DNS seguro
GET  /api/dns/stats         # Estadísticas de DNS
```

### **📊 Estadísticas**
```http
GET /api/stats/user         # Estadísticas del usuario
GET /api/stats/bandwidth    # Uso de ancho de banda
GET /api/stats/connections  # Historial de conexiones
```

## 🛠️ Tecnologías

- **Node.js** 16+ - Runtime de JavaScript
- **Express.js** - Framework web
- **SQLite** - Base de datos ligera
- **SSH2** - Conexión SSH a Mikrotik
- **JWT** - Autenticación segura
- **Bcrypt** - Hash de contraseñas
- **Winston** - Logging avanzado
- **Joi** - Validación de datos

## 🔧 Scripts Disponibles

```bash
npm start          # Iniciar servidor producción
npm run dev        # Iniciar servidor desarrollo
npm test           # Ejecutar tests
npm run setup      # Configurar base de datos
npm run migrate    # Ejecutar migraciones
npm run backup     # Backup de base de datos
npm run lint       # Verificar código
```

## 📁 Estructura del Proyecto

```
nubolink-api/
├── config/          # Configuraciones
├── controllers/     # Controladores de rutas
├── middleware/      # Middleware personalizado
├── models/          # Modelos de datos
├── routes/          # Definición de rutas
├── services/        # Servicios de negocio
├── utils/           # Utilidades
├── scripts/         # Scripts de setup
├── database/        # Esquemas y migraciones
├── tests/           # Tests automatizados
└── docs/            # Documentación
```

## 🔒 Seguridad

- ✅ **JWT Authentication** con refresh tokens
- ✅ **Rate Limiting** para prevenir ataques
- ✅ **Helmet.js** para headers de seguridad
- ✅ **CORS** configurado correctamente
- ✅ **Input validation** con Joi
- ✅ **SSH key management** seguro
- ✅ **Password hashing** con bcrypt

## 🐳 Docker

```bash
# Construir imagen
docker build -t nubolink-api .

# Ejecutar contenedor
docker-compose up -d
```

## 📚 Documentación

- [**Guía de Setup**](docs/SETUP.md) - Configuración detallada
- [**API Reference**](docs/API.md) - Documentación completa de API
- [**Deployment**](docs/DEPLOYMENT.md) - Guía de despliegue
- [**Mikrotik Integration**](docs/MIKROTIK.md) - Configuración Mikrotik

## 🧪 Testing

```bash
# Ejecutar todos los tests
npm test

# Tests en modo watch
npm run test:watch

# Tests con coverage
npm run test:coverage
```

## 🚀 Deployment

### **Servidor Ubuntu**
```bash
# Clonar repositorio
git clone https://github.com/yourusername/nubolink-api.git

# Ejecutar script de setup
chmod +x scripts/deploy.sh
./scripts/deploy.sh
```

### **Variables de Producción**
- Configurar SSL con Let's Encrypt
- Setup de Nginx como reverse proxy
- PM2 para gestión de procesos
- Backup automático con cron

## 🤝 Contribuir

1. **Fork** el proyecto
2. **Crear** rama feature (`git checkout -b feature/AmazingFeature`)
3. **Commit** cambios (`git commit -m 'Add AmazingFeature'`)
4. **Push** a la rama (`git push origin feature/AmazingFeature`)
5. **Abrir** Pull Request

## 📝 Changelog

### **v1.0.0** (2024-09-15)
- ✅ API completa para VPN y DNS
- ✅ Integración con Mikrotik via SSH
- ✅ Autenticación JWT
- ✅ Base de datos SQLite
- ✅ Docker support
- ✅ Tests automatizados

## 📄 Licencia

Este proyecto está bajo la licencia **MIT**. Ver [LICENSE](LICENSE) para más detalles.

## 📞 Soporte

- **GitHub Issues**: [Reportar problema](https://github.com/yourusername/nubolink-api/issues)
- **Email**: support@nubolink.com
- **Discord**: [NuboLink Community](https://discord.gg/nubolink)

---

**Hecho con ❤️ por el equipo NuboLink**

> 💡 **Tip**: Para la aplicación iOS companion, visita [NuboProtect iOS](https://github.com/yourusername/nuboprotect-ios)
