package com.project.backend.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.project.backend.model.Address;



@Repository
public interface AddressRepository extends JpaRepository<Address, Long> {


    Address findByUser_UserId(Long userId);

}
