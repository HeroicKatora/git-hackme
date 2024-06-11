const init_window = function (project_list, project_username) {
	let domain = new URL(window.location);
	domain.username = project_username;

	for (let item of document.getElementsByClassName('git-hackme-project-join-link')) {
		console.log(item);
		const preText = item.getElementsByClassName('git-hackme-project-join-pre')[0];
		const buttonText = item.getElementsByClassName('git-hackme-project-join-button')[0];

		buttonText.onclick = function() {
			navigator.clipboard.writeText(preText.innerText);
		};
	}

	window.onload = () => {
		for (let mn of project_list) {
			document.getElementById(`cmd-join-${mn}`).innerText = `git-hackme clone "${domain}/${mn}"`;
		}
	};
};

export { init_window };
