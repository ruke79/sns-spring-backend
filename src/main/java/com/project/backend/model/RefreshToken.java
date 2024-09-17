package com.project.backend.model;

import java.util.Date;
import java.time.Instant;
import java.time.LocalDateTime;

import io.hypersistence.utils.hibernate.id.Tsid;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;


@Entity
@Data
@Table(name = "refreshtoken")
public class RefreshToken {

    @Id @Tsid
    @Column(name="id")
    private Long id;

    @OneToOne
    @JoinColumn(name="user_id", referencedColumnName = "user_id")
    User user;

    @Column(nullable=false, unique=true)
    private String token;

    @Column(nullable=false)
    //private Instant expiryDate;    
    private Date expiryDate;    

    
}
