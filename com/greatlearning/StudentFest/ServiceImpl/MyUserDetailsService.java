package com.greatlearning.StudentFest.ServiceImpl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.greatlearning.StudentFest.Entity.MyUserDetails;
import com.greatlearning.StudentFest.Entity.User;
import com.greatlearning.StudentFest.Repo.UserRepo;

public class MyUserDetailsService implements UserDetailsService{

	@Autowired
	private UserRepo userRepo;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		User user = userRepo.findByUsername(username);
		if(user==null)
			throw new UsernameNotFoundException("User not found");
		return new MyUserDetails(user);
	}
}
