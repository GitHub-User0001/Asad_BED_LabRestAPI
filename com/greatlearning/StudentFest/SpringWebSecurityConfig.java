package com.greatlearning.StudentFest;


import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.greatlearning.StudentFest.Entity.Role;
import com.greatlearning.StudentFest.Entity.User;
import com.greatlearning.StudentFest.Repo.RoleRepo;
import com.greatlearning.StudentFest.Repo.UserRepo;
import com.greatlearning.StudentFest.ServiceImpl.MyUserDetailsService;


@Configuration
@EnableWebSecurity
public class SpringWebSecurityConfig extends WebSecurityConfigurerAdapter{

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(authenticationProvider());
	}

	@Bean
	public PasswordEncoder encoder()
	{
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	public UserDetailsService userDetailsService()
	{
		return new MyUserDetailsService();
	}
	
	@Bean
	public DaoAuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider dao = new DaoAuthenticationProvider();
		dao.setUserDetailsService(userDetailsService());
		dao.setPasswordEncoder(encoder());
		return dao;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
		http.authorizeRequests()
		.antMatchers(HttpMethod.GET,"/api/students/fecthAllStudents","/api/students/fecthStudentById","/api/students/showformForAdd")
		.hasAnyAuthority("USER","ADMIN")
		.antMatchers(HttpMethod.POST,"/api/students/saveStudent")
		.hasAnyAuthority("USER","ADMIN").and()
		.authorizeRequests()
		.antMatchers("/api/students/showformForUpdate","/api/students/deleteStudentById")
		.hasAuthority("ADMIN").anyRequest().authenticated()
		.and().formLogin().loginProcessingUrl("/login").permitAll()
		.and().logout().logoutSuccessUrl("/login").permitAll().and()
		.exceptionHandling().accessDeniedPage("/api/students/403");
	}
	
	@Autowired
	private RoleRepo roleRepo;
	
	@Autowired
	private UserRepo userRepo;
	
}	