package com.project.backend.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AddressDTO {

    private String id;

    private String firstname;

    private String lastname;

    private String address1;

    private String address2;

    private String city;

    private String state;

    private String zipCode;
    
    private String country;

    private String phoneNumber;

    private boolean active;
}
