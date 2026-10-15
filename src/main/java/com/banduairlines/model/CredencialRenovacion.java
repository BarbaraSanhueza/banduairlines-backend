
package com.banduairlines.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

@Entity
@Table(
        name = "credenciales_renovacion",
        indexes = {
                @Index(
                        name = "idx_credencial_usuario",
                        columnList = "usuario_id"
                )
        }
)
@Getter
@Setter
@NoArgsConstructor
public class CredencialRenovacion {

    // Identificador unico de la credencial.
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Usuario propietario de la credencial.
    @ManyToOne(
            fetch = FetchType.LAZY,
            optional = false
    )
    @JoinColumn(
            name = "usuario_id",
            nullable = false
    )
    private Usuario usuario;

    // Hash SHA-256 del refresh token.
    // Nunca almacenamos el token original.
    @Column(
            name = "token_hash",
            nullable = false,
            unique = true,
            length = 64
    )
    private String tokenHash;

    // Momento de creacion.
    @Column(
            name = "fecha_creacion",
            nullable = false,
            updatable = false
    )
    private Instant fechaCreacion;

    // Momento de expiracion.
    @Column(
            name = "fecha_expiracion",
            nullable = false
    )
    private Instant fechaExpiracion;

    // Momento de revocacion, si existe.
    @Column(name = "fecha_revocacion")
    private Instant fechaRevocacion;

    // Explica por que fue revocada.
    @Column(
            name = "motivo_revocacion",
            length = 100
    )
    private String motivoRevocacion;

    // Comprueba si la credencial sigue vigente.
    public boolean estaVigente(Instant ahora) {

        return fechaRevocacion == null
                && fechaExpiracion != null
                && fechaExpiracion.isAfter(ahora);
    }
}
