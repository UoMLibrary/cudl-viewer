function toggleDiv(divid) {
	if (document.getElementById(divid).style.display == 'none') {
		document.getElementById(divid).style.display = 'block';
	} else {
		document.getElementById(divid).style.display = 'none';
	}
}

$(document).ready(function() {
$(".iframe").fancybox({
	'width'				: '75%',
	'height'			: '75%',
	'autoScale'			: false,
	'transitionIn'		: 'none',
	'transitionOut'		: 'none',
	'type'				: 'iframe',
	'titleShow'			: false
});
});