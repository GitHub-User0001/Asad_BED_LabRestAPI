<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
	pageEncoding="ISO-8859-1"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="ISO-8859-1">
<link rel="stylesheet"
	href="https://stackpath.bootstrapcdn.com/bootstrap/4.2.1/css/bootstrap.min.css"
	integrity="sha384-GJzZqFGwb1QTTN6wy59ffF1BuGJpLSa9DkKMp0DgiMDm4iYMj70gZWKYbI706tWS"
	crossorigin="anonymous">
<title>Save Student</title>
</head>
<body>
	<div class='container'>
		<h3>Student Directory</h3>

		<hr>

		<p class="h4 mb-4">Enter Student</p>

		<form action="/api/students/saveStudent" method="POST">

			<!-- Add hidden form field to handle update -->
			<input type="hidden" name="id" value="${Student.id}" />

			<div class="form-inline">
				<input type="text" name="fname" value="${Student.fname}"
					class="form-control mb-4 col-4" placeholder="First Name">
			</div>
			
			<div class="form-inline">
				<input type="text" name="lname" value="${Student.lname}"
					class="form-control mb-4 col-4" placeholder="Last Name">
			</div>

			<div class="form-inline">
				<input type="text" name="course" value="${Student.course}"
					class="form-control mb-4 col-4" placeholder="Course">
			</div>

			<div class="form-inline">
				<input type="text" name="country" value="${Student.country}"
					class="form-control mb-4 col-4" placeholder="Country">
			</div>
			
			<input name="${_csrf.parameterName }" type="hidden"
				value="${_csrf.token}" />
			<button type="submit" class="btn btn-info col-2">Save</button>

		</form>

		<hr>
		<a href="/api/students/fecthAllStudents">Back to Students List</a>

	</div>

</body>
</html>