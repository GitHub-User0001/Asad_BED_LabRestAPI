package com.greatlearning.StudentFest.Repo;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.greatlearning.StudentFest.Entity.Role;

@Repository
public interface RoleRepo extends JpaRepository<Role, Integer>{

}
