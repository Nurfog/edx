class @HTMLModule

  constructor: (@element) ->
    @el = $(@element)
    JavascriptLoader.executeModuleScripts(@el)
    Collapsible.setCollapsibles(@el)
    if MathJax?
	    MathJax.Hub.Queue ["Typeset", MathJax.Hub, @el[0]]

  $: (selector) ->
    $(selector, @el)
