$(document).ready(function () {
    
    var $select_allow = $('select[name="allow"]')

    $select_allow.change(function (ev) {
        var $this = $(this);
        var $select_ttl = $('select[name="ttl"]');
        var $fiedsets = $("#fieldset-exported-ax-attrs,#fieldset-exported-sreg-attrs")
        var $checkboxes = $fiedsets.find('input[type="checkbox"]')
        if ($this.val() == 'always') {
            $select_ttl.attr('disabled', null)
            $checkboxes.attr('disabled', null)
        } else {
            $select_ttl.attr('disabled', 'disabled')
            $checkboxes.attr('disabled', 'disabled')
        }
        return true
    })
    
    $select_allow
       .val($select_allow.data('default-value'))
       .change()

    return;
}) 
