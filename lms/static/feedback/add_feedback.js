/* When the user clicks on the button, 
toggle between hiding and showing the dropdown content */
function dropupError() {
	const dropupElement = document.getElementById("dropupError")
	dropupElement.classList.toggle("show");

	// if (dropupElement.classList.contains("show")) {
	// 	const btnSubmit = document.getElementById('submit-feedback')
	// 	const comment = document.getElementById('comment')
	// 	btnSubmit.setAttribute('disabled', 'disabled');
	// 	comment.addEventListener('input', (e)=>{
	// 		if (e.target.value.length > 0){
	// 			btnSubmit.removeAttribute('disabled')
	// 		}
	// 	})
	//   } 
}




const addFeedbackForm = async () => {
	// Get form html form api and append to body using fetch
	let url = this.LMSHost + '/feedback/';
	await fetch(url, {
		method: "GET",
		headers: {},
		credentials: 'include'
	})
	.then(response => response.text())
	.then(html => {
		document.body.insertAdjacentHTML('beforeend', html);
	});

	
}

const initFUNiXFeedback = (LMSHost = '', isMFE = false) => {	
	this.LMSHost = LMSHost;
	this.isMFE = isMFE;

	addFeedbackForm()
};





const handlerSubmit  = (event)=>{
	event.preventDefault()
	url =this.LMSHost + '/api/feedback/create'
	const lesson_url = window.location.href
	const csrf_token = document.getElementById('csrf_token').value
	const feedbackcategory = document.getElementById('feedback-category').value
	const comment = document.getElementById('comments').value
	const email = document.getElementById('email').value
	const formData = new FormData();
	const parts = lesson_url.split('/');
	const course_id = parts[4]
	formData.append('attachment', fileInput.files[0]);
	formData.append('category_id', feedbackcategory)
	formData.append('content' , comment)
	formData.append('email' , email)
	formData.append('lesson_url' , lesson_url)
	formData.append('course_id', course_id)
	fetch(url, {
		method: 'POST', 
		headers: {
		  'X-CSRFToken': csrf_token
		},
		body: formData,
	  })
		.then((response) => {
		  if (response.status === 200) {
			return response.json(); 
		  } else {
			throw new Error(`API request failed with status: ${response.status}`);
		  }
		})
		.then((data) => {
		 console.log('API Response:', data);
		})
		.catch((error) => {
		  console.error('API Request Error:', error);
		});

}