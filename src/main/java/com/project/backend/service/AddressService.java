package com.project.backend.service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.project.backend.model.Address;
import com.project.backend.model.User;
import com.project.backend.dto.AddressDTO;
import com.project.backend.repository.AddressRepository;
import com.project.backend.repository.UserRepository;
import com.project.backend.security.request.AddressRequest;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class AddressService {
    
    private final UserRepository userRepository;

    @Autowired
    public AddressService( UserRepository userRepository) {        
        this.userRepository = userRepository;
    }

    public void saveAddress(AddressRequest request, String username) {

        User user = userRepository.findByUserName(username)
                .orElseThrow(() -> new RuntimeException("User not found"));        
        
        deepCopyAddress(user.getAddress(), request.getAddress());

        
        userRepository.save(user);
        
    }

    static public void deepCopyAddress(Address address, AddressDTO src) {

        address.setAddress1(src.getAddress1());
        address.setAddress2(src.getAddress2());
        address.setCity(src.getCity());
        address.setState(src.getState());
        //address.setCountry(src.getCountry());
        //address.setFirstname(src.getFirstname());
        //address.setLastname(src.getLastname());
        //address.setPhoneNumber(src.getPhoneNumber());
        address.setZipCode(src.getZipCode());
    }

    static public void deepCopyAddressDTO(AddressDTO address, Address src) {

        address.setId(Long.toString(src.getAddressId()));
        address.setAddress1(src.getAddress1());
        address.setAddress2(src.getAddress2());
        address.setCity(src.getCity());
        address.setState(src.getState());
        //address.setCountry(src.getCountry());
        //address.setFirstname(src.getFirstname());
        //address.setLastname(src.getLastname());
        //address.setPhoneNumber(src.getPhoneNumber());
        address.setZipCode(src.getZipCode());
    }

}
