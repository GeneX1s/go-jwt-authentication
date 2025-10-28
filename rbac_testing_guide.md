# RBAC API Testing Guide

## Overview
This guide provides comprehensive testing instructions for the Role-Based Access Control (RBAC) implementation in Go.

## Table of Contents
1. [Setup](#setup)
2. [Authentication](#authentication)
3. [Role Hierarchy](#role-hierarchy)
4. [API Endpoints](#api-endpoints)
5. [Testing Scenarios](#testing-scenarios)
6. [Security Features](#security-features)

---

## Setup

### Dependencies
```bash
go get github.com/gin-gonic/gin
go get github.com/dgrijalva/jwt-go
```

### Run the Server
```bash
go run main.go
```

Server will start on `http://localhost:8080`

---

## Authentication

### Test Users

| Username | Password | Role | Access Level |
|----------|----------|------|--------------|
| admin | admin123 | admin | Full system access |
| manager | manager123 | manager | Read/write reports, view users |
| operator | operator123 | operator | Read-only for users and reports |
| viewer | viewer123 | viewer | Read-only reports |

---

## Role Hierarchy

### Permissions Matrix

| Permission | Admin | Manager | Operator | Viewer |
|------------|-------|---------|----------|--------|
| users:read | ✅ | ✅ | ✅ | ❌ |
| users:write | ✅ | ❌ | ❌ | ❌ |
| users:delete | ✅ | ❌ | ❌ | ❌ |
| reports:read | ✅ | ✅ | ✅ | ✅ |
| reports:write | ✅ | ✅ | ❌ | ❌ |
| roles:manage | ✅ | ❌ | ❌ | ❌ |
| audit:view | ✅ | ✅ | ❌ | ❌ |
| admin:access | ✅ | ❌ | ❌ | ❌ |

---

## API Endpoints

### 1. Login
**POST** `/api/v1/login`

**Request:**
```bash
curl -X POST http://localhost:8080/api/v1/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "admin123"
  }'
```

**Response:**
```json
{
  "message": "Login successful",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "username": "admin",
    "roles": ["admin"],
    "permissions": [
      "users:read",
      "users:write",
      "users:delete",
      "reports:read",
      "reports:write",
      "roles:manage",
      "audit:view",
      "admin:access"
    ]
  }
}
```

---

### 2. Get Current User Info
**GET** `/api/v1/me`

**Request:**
```bash
curl -X GET http://localhost:8080/api/v1/me \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

**Response:**
```json
{
  "username": "admin",
  "roles": ["admin"],
  "permissions": ["users:read", "users:write", ...]
}
```

---

### 3. View Reports (All Roles)
**GET** `/api/v1/reports`

**Required Permission:** `reports:read`

**Request:**
```bash
curl -X GET http://localhost:8080/api/v1/reports \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

**Response:**
```json
{
  "message": "Reports data",
  "reports": [
    {
      "id": 1,
      "name": "Monthly Sales",
      "type": "sales"
    },
    {
      "id": 2,
      "name": "User Activity",
      "type": "analytics"
    }
  ]
}
```

---

### 4. Generate Report (Admin/Manager Only)
**POST** `/api/v1/reports`

**Required Permission:** `reports:write`

**Request:**
```bash
curl -X POST http://localhost:8080/api/v1/reports \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -H "Content-Type: application/json" \
  -d '{
    "report_type": "monthly_sales",
    "date_range": "2024-01-01 to 2024-01-31"
  }'
```

**Response:**
```json
{
  "message": "Report generated successfully",
  "report": {
    "type": "monthly_sales",
    "generated": "2025-10-28T10:30:00Z",
    "status": "completed"
  }
}
```

---

### 5. List Users
**GET** `/api/v1/users`

**Required Permission:** `users:read`

**Request:**
```bash
curl