package com.greatlearning.StudentFest.Controller;

import java.security.Principal;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import com.greatlearning.StudentFest.Entity.Student;
import com.greatlearning.StudentFest.ServiceImpl.StudentService;

@Controller
@RequestMapping("/api/students")
public class StudentController {

	@Autowired
	private StudentService studentService;

	@GetMapping("/fecthAllStudents")
	public String fecthAllStudents(Map<String, List<Student>> map) {

		List<Student> students = this.studentService.fetchAllStudents();
		map.put("Students", students);
		return "studentList";
	}

	@GetMapping("/fecthStudentById")
	public String fetchStudentById(@RequestParam("studentId") int id) {
		studentService.findStudentById(id);
		return "student";
	}

	@RequestMapping("/deleteStudentById")
	public String deleteStudentById(@RequestParam("id") int id) {
		studentService.deleteById(id);
		return "redirect:fecthAllStudents";
	}

	@RequestMapping("/saveStudent")
	public String saveStudent(Student student) {
		Student theStudent;

		if (student.getId() != 0) {
			theStudent = studentService.findStudentById(student.getId());
			theStudent.setFname(student.getFname());
			theStudent.setLname(student.getLname());
			theStudent.setCountry(student.getCountry());
			theStudent.setCourse(student.getCourse());
		} else
			theStudent = new Student(student.getFname(), student.getLname(), student.getCourse(), student.getCountry());

		studentService.saveStudent(theStudent);
		return "redirect:fecthAllStudents";
	}
	
	@RequestMapping("/showformForAdd")
	public String showformForAdd(Model theModel){
		
		Student theStudent = new Student();
		
		theModel.addAttribute("Student", theStudent);
		return "studentForm";
	}
	
	@RequestMapping("/showformForUpdate")
	public String showformForUpdate(@RequestParam("studentId") int id, Model theModel) {
		
		Student theStudent = studentService.findStudentById(id);
		
		theModel.addAttribute("Student", theStudent);
		return "studentForm";
	}
	
	@RequestMapping(value = "/403")
	public ModelAndView accesssDenied(Principal user) {

		ModelAndView model = new ModelAndView();

		System.out.println(user);
		if (user != null) {
			model.addObject("msg", "Hi " + user.getName() 
			+ ", you don't have permission to access this page!");
		} else {
			model.addObject("msg", 
			"You have permission to access this page!");
		}

		model.setViewName("403");
		return model;

	}

}
