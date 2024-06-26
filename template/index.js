const init_window = function (project_items, project_username) {
	let domain = new URL(window.location);
	domain.username = project_username;

	let title = document.getElementById('git-hackme-global-title');
	if (title) {
		title.innerText += ` shared at ${window.location}`;
	}

	for (let item of document.getElementsByClassName('git-hackme-project-join-link')) {
		const preText = item.getElementsByClassName('git-hackme-project-join-pre')[0];
		const buttonText = item.getElementsByClassName('git-hackme-project-join-button')[0];

		buttonText.onclick = function() {
			navigator.clipboard.writeText(preText.innerText);
		};
	}

	window.onload = () => {
		for (let mn in project_list) {
			let description = project_list[mn];

			let project = document.getElementById(`git-hackme-project-${mn}`);
			let project_join = document.getElementById(`cmd-join-${mn}`);
			let title = project.querySelector('.git-hackme-title');

			if (description.folder) {
				project_join.innerText = `git hackme clone "${domain}/${mn}" ${description.folder}`;
			} else {
				project_join.innerText = `git hackme clone "${domain}/${mn}"`;
			}

			if (description.name) {
				title.innerText = `${description.name} (${mn})`;
			}
		}
	};
};

export { init_window };
