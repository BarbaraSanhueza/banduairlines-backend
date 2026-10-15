package com.banduairlines.model;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import com.banduairlines.model.enums.RolUsuario;
import com.banduairlines.model.enums.TipoDocumento;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "usuarios")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Usuario {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long idUsuario;

    @Column(name = "email", nullable = false, unique = true, length = 150)
    private String correo;

    @Column(name = "password_hash", nullable = false)
    private String contrasenaHash;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    @Builder.Default
    private RolUsuario rol = RolUsuario.PASAJERO; 

    @Column(name = "nombre", nullable = false, length = 80)
    private String nombres;

    @Column(name = "apellido", nullable = false, length = 80)
    private String apellidos;

    @Enumerated(EnumType.STRING)
    @Column(name = "tipo_documento")
    private TipoDocumento tipoDocumento; 

    @Column(name = "numero_documento", length = 30)
    private String numeroDocumento; 

    @Column(name = "fecha_nacimiento")
    private LocalDate fechaNacimiento; 

    @Column(length = 30)
    private String telefono;

    @Column(nullable = false)
    @Builder.Default
    private Boolean activo = true;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime fechaCreacion;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime fechaActualizacion;

    // --- RELACIONES ---

    @OneToOne(mappedBy = "usuario", cascade = CascadeType.ALL, fetch = FetchType.LAZY, orphanRemoval = true)
    private CuentaFidelizacion cuentaFidelizacion;

    @OneToMany(mappedBy = "usuario", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private List<Reserva> reservas = new ArrayList<>();
}
