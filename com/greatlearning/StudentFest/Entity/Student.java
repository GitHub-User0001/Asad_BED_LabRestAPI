package com.greatlearning.StudentFest.Entity;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;

import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Data
@NoArgsConstructor
public class Student {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private int id;
	private String fname;
	private String lname;
	private String course;
	private String country;
	public Student(String fname, String lname, String course, String country) {
		super();
		this.fname = fname;
		this.lname = lname;
		this.course = course;
		this.country = country;
	}
	
	
	
}
