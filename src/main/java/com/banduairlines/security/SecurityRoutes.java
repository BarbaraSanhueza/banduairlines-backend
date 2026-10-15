package com.banduairlines.security;

public final class SecurityRoutes {

    private SecurityRoutes() {}

    public static final String API = "/api/v1";

    /** Públicas para cualquier método HTTP. */
    public static final String[] PUBLICAS = {
            API + "/health",                  // INTEGRA: endpoint de salud
            "/actuator/health",               // INTEGRA: healthcheck del despliegue (Actuator)
            "/actuator/health/**",
            API + "/pagos/notificaciones"     // PAGOS: callback servidor-a-servidor de Flow (no trae token)
    };

    /** Rutas publicas solamente para peticiones POST. (C) */
    public static final String[] PUBLICAS_POST = {
            API + "/auth/registro",
            API + "/auth/inicio-sesion",
            API + "/auth/renovacion",
            API + "/auth/recuperaciones"
    };

    /** Públicas solo para GET. */
    public static final String[] PUBLICAS_GET = {
            API + "/busqueda/**",             // BÚSQUEDA: el visitante busca vuelos sin cuenta (ruta propuesta)
            "/v3/api-docs/**",
            "/swagger-ui/**",
            "/swagger-ui.html"
            // PENDIENTE: rutas de invitado de RESERVA, PAGOS y CHECKIN. Cada equipo las propone por PR (D-03).
    };

    /** Solo rol ADMINISTRADOR. */
    public static final String[] SOLO_ADMIN = {
            API + "/admin/**"                 // ADMIN y REPORTES bajo /admin/**; gestión en /admin/tracking/** (Tracking de pasajero en API + "/tracking/**", requiere autenticación, NO pública)
    };

    /** Recuperacion de contraseña mediante codigo temporal. (C) */
    public static final String[] RECUPERACION_CON_CODIGO = {
            API + "/auth/recuperaciones/*"
    };

    /** Gestion de administradores: solo SUPERADMIN. (C) */
    public static final String[] SOLO_SUPERADMIN = {
            API + "/admin/cuentas/**"
    };

    /** Funcionalidades exclusivas de pasajeros registrados. (C) */
    public static final String[] SOLO_PASAJERO = {
            API + "/cuentas/actual/fidelizacion",
            API + "/cuentas/actual/fidelizacion/**",
            API + "/fidelizacion/**"
    };

    /** Perfil de usuarios PASAJERO y ADMINISTRADOR. (C) */
    public static final String[] PERFIL_CUENTA = {
            API + "/cuentas/actual",
            API + "/cuentas/actual/perfil",
            API + "/cuentas/actual/contrasena",
            API + "/cuentas/actual/cambio-correo/**"
    };

    /** Cierre de sesion: requiere un access token. (C) */
    public static final String[] CIERRE_SESION = {
            API + "/auth/cierre-sesion"
    };
}
