<template>
    <div class="backend-content" id="content">
        <div class="column col-6 col-xs-12">
            <h3 class="s-title">Manage MISP IOCs</h3>
            <div>
                Here you can add IOCs from your MISP instances. To do so, you first need to fullfil the "Add a new MISP instance" form. Then go to the "Existing instances" tab and scroll to the desired instance.
                Finally, just fill the parameters as you wish and click on the "Import IOCs" button. All the IOCs that are not already in the database will be added.
                Note that only IOCs (attributes) that belongs to the "Network activity" category will be inserted.
            </div>
            <ul class="tab tab-block">
                <li class="tab-item">
                    <a href="#" v-on:click="switch_tab('addmisp')" v-bind:class="{ active: tabs.addmisp }">Add instance</a>
                </li>
                <li class="tab-item">
                    <a href="#" v-on:click="switch_tab('instances')" v-bind:class="{ active: tabs.instances }">Existing instances</a>
                </li>
            </ul>
            <div v-if="tabs.addmisp">
                <h5>Add a new MISP instance</h5>
                <div class="misp-form">
                    <label class="misp-label">Name</label><span>:</span>
                    <input class="misp-input" type="text" ref="misp_name" placeholder="Enter the name to give to your MISP instance" v-model="mispinst.name" required>
                    <label class="misp-label">URL</label><span>:</span>
                    <input class="misp-input" type="text" ref="misp_url" placeholder="Enter your MISP instance URL" v-model="mispinst.url" required>
                    <label class="misp-label">API key</label><span>:</span>
                    <input class="misp-input" type="text" ref="misp_key" placeholder="Enter the API key to use" v-model="mispinst.key" required>
                    <label class="misp-label">Verify certificate</label><span>:</span>
                    <div style="flex:50%"><input class="misp-input" style="margin-right: 5px;" type="checkbox" id="checkbox" v-model="mispinst.ssl"><label for="checkbox">{{ mispinst.ssl }}</label></div>
                </div>
                <button class="btn-primary btn col-12" v-on:click="add_misp_instance()">Add MISP instance</button>
                <div class="form-group" v-if="addedInstance.length>0">
                    <div class="toast toast-success">
                        ✓ MISP instance added successfully.
                    </div>
                </div>
                <div v-if="errorsInstance.length>0">
                    <div class="form-group">
                        <div class="toast toast-error">
                            ✗ MISP instance not added, see details below.
                        </div>
                    </div>
                    <div class="form-group">
                        <table class="table table-striped table-hover">
                            <thead>
                                <tr>
                                    <th>Name</th>
                                    <th>URL</th>
                                    <th>API key</th>
                                    <th>Reason</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr v-for="e in errorsInstance" v-bind:key="e.name">
                                    <td>{{ e.name }}</td>
                                    <td>{{ e.url }}</td>
                                    <td>{{ e.apikey }}</td>
                                    <td>{{ e.message }}</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
            <div class="form-group" v-if="tabs.instances">
                <div v-if="mispInstances.length>0">
                    <div v-for="r in mispInstances" v-bind:key="r.id">
                        <div style="position: relative">
                            <input class="misp-name" :id="r.id + 'name'" v-bind:value="r.name" v-model="r.name" disabled="disabled" required>
                            <button class="btn btn-sm" :id="r.id + 'edit'" :ref="r.id + 'edit'" v-on:click="edit_misp_instance(r)" style="position: absolute; right:120px;">Edit instance</button>
                            <button class="btn btn-sm" :id="r.id + 'delete'" :ref="r.id + 'delete'" v-on:click="remove_or_cancel_edit_misp_instance(r)" style="position: absolute; right:0;">Delete instance</button>
                        </div>
                        <div class="misp-form">
                            <label class="misp-label">URL</label><span>:</span>
                            <input class="misp-input" :id="r.id + 'insturl'" v-bind:value="r.url" v-model="r.url" disabled="disabled" required>
                            <label class="misp-label">API Key</label><span>:</span>
                            <input class="misp-input" :id="r.id + 'instkey'" v-bind:value="r.apikey" v-model="r.apikey" disabled="disabled" required>
                            <label class="misp-label">Verify certificate</label><span>:</span>
                            <div style="flex:50%;"><input class="misp-input" :id="r.id + 'check'" type="checkbox" v-bind:value="r.verifycert" v-model="r.verifycert" style="visibility: hidden; width: 0;"><label v-bind:value="r.verifycert">{{ r.verifycert == 0 ? 'false' : 'true'}}</label></div>
                            <label class="misp-label">Limit</label><span>:</span>
                            <input class="misp-input" type="number" step="1" min="0" :id="r.id + 'limit'" placeholder="Enter the maximum number of IOCs to retrieve">
                            <label class="misp-label">Page index</label><span>:</span>
                            <input class="misp-input" type="number" step="1" min="0" :id="r.id + 'page'" placeholder="Enter the page index where to start retrieving IOCs">
                            <button class="btn btn-sm" :id="r.id + 'import'" v-on:click="import_misp_iocs(r)">Import IOCs</button>
                        </div>
                    </div>
                    <div class="form-group" v-if="addedInstance.length>0">
                    <div class="toast toast-success">
                        ✓ MISP instance edited successfully.
                    </div>
                </div>
                <div v-if="errorsInstance.length>0">
                    <div class="form-group">
                        <div class="toast toast-error">
                            ✗ MISP instance count not be edited, see details below.
                        </div>
                    </div>
                    <div class="form-group">
                        <table class="table table-striped table-hover">
                            <thead>
                                <tr>
                                    <th>Name</th>
                                    <th>URL</th>
                                    <th>API key</th>
                                    <th>Reason</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr v-for="e in errorsInstance" v-bind:key="e.name">
                                    <td>{{ e.name }}</td>
                                    <td>{{ e.url }}</td>
                                    <td>{{ e.apikey }}</td>
                                    <td>{{ e.message }}</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
                </div>
                <div v-else>
                    <p>No MISP instance found. Click the "Add" button to add new MISP instance.</p>
                    <button class="btn btn-sm" v-on:click="switch_tab('addmisp')" v-bind:class="{ active: tabs.addmisp }">Add a new instance</button>
                </div>
            </div>
          
            <div class="form-group" v-if="imported.length>0">
                <div class="toast toast-success">
                    ✓ {{imported.length}} IOC<span v-if="imported.length>1">s</span> imported successfully.
                </div>
                <div class="form-group">
                    <table class="table table-striped table-hover">
                        <thead>
                            <tr>
                                <th>Indicator</th>
                                <th>Type</th>
                                <th>Tag</th>
                                <th>TLP</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr v-for="i in imported" v-bind:key="i.ioc">
                                <td>{{ i.ioc }}</td>
                                <td>{{ i.type }}</td>
                                <td>{{ i.tag }}</td>
                                <td>{{ i.tlp }}</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
            <div v-if="errors.length>0">
                <div class="form-group">
                    <div class="toast toast-error">
                        ✗ {{errors.length}} IOC<span v-if="errors.length>1">s</span> not imported, see details below.
                    </div>
                </div>
                <div class="form-group">
                    <table class="table table-striped table-hover">
                        <thead>
                            <tr>
                                <th>Indicator</th>
                                <th>Importation error</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr v-for="e in errors" v-bind:key="e.ioc">
                                <td>{{ e.ioc }}</td>
                                <td>{{ e.message }}</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
            <div v-else-if="type_tag_error==true">
                <div  class="form-group">
                    <div class="toast toast-error">
                        ✗ IOC(s) not imported, see details below.
                    </div>
                </div>
                <div  class="form-group">
                    <div class="empty">
                        <p class="empty-title h5">Please select a tag and a type.</p>
                        <p class="empty-subtitle">If different IOCs types, select "Unknown (regex parsing)".</p>
                    </div>
                </div>
            </div>
        </div>
    </div>
</template>

<script>
import axios from 'axios'

export default {
    name: 'managemisp',   
    data() {
        return { 
            errors:[],
            imported:[],
            errorsInstance:[],
            addedInstance:[],
            mispinst:{name:'', url:'',key:'', ssl:false},
            mispInstances:[],
            tabs: { "addmisp" : true, "instances" : false },
            jwt:"",
            type_tag_error: false
        }
    },
    props: { },
    methods: {
        add_misp_instance: function()
        {  
            this.errors = [];
            this.imported = [];
            this.errorsInstance = []
            this.addedInstance = []
            if (this.mispinst["name"] != "" && this.mispinst["url"] != "" && this.mispinst["key"] != "")
            {
                axios.post(`/api/misp/add`, { data: { instance: this.mispinst } }, { headers: {'X-Token': this.jwt} }).then(response => {
                    if(response.data.status){
                        this.addedInstance.push(response.data);
                    } else if (response.data.message){
                        this.errorsInstance.push(response.data);
                    }
                })
                .catch(err => (console.log(err)))
            }
            else
            {
                console.log(this.mispinst["name"]);
                console.log(this.mispinst["url"]);
                console.log(this.mispinst["key"]);
            }
        },
        edit_misp_instance (elem)
        {
            if (document.getElementById(elem.id+'insturl').disabled == false)
            {   // The misp instance was in edit mode
                   
                this.errors = [];
                this.imported = [];
                this.errorsInstance = []
                this.addedInstance = []
                if (elem["name"] != "" && elem["url"] != "" && elem["key"] != "")
                {
                    axios.post(`/api/misp/edit`, { data: { instance: elem } }, { headers: {'X-Token': this.jwt} }).then(response => {
                        if(response.data.status){
                            this.addedInstance.push(response.data);
                        } else if (response.data.message){
                            this.errorsInstance.push(response.data);
                        }
                    })
                    .catch(err => (console.log(err)))
                }
                this.cancel_edit_misp(elem);
            }
            else
            {   // the misp instance should enter in edit mode

                document.getElementById(elem.id+'edit').innerText = 'Validate edit';
                document.getElementById(elem.id+'delete').innerText = 'Cancel edit';
                document.getElementById(elem.id+'name').disabled = false;
                document.getElementById(elem.id+'insturl').disabled = false;
                document.getElementById(elem.id+'instkey').disabled = false;
                document.getElementById(elem.id+'limit').disabled = true;
                document.getElementById(elem.id+'page').disabled = true;
                document.getElementById(elem.id+'import').disabled = true;
                document.getElementById(elem.id+'check').style = "margin-right: 5px;";
            }
        },
        remove_or_cancel_edit_misp_instance(elem)
        {
            if (document.getElementById(elem.id+'insturl').disabled == false)
            {   // The misp instance was in edit mode

                this.cancel_edit_misp(elem)
            }
            else
            {   // The misp instance should be delete

                axios.get(`/api/misp/delete/${elem.id}`, { timeout: 10000, headers: {'X-Token': this.jwt} })
                .then(response => {
                    if(response.data.status){
                        this.mispInstances = this.mispInstances.filter(function(el) { return el != elem; }); 
                    }
                })
                .catch(err => (console.log(err)))
            }
        },
        cancel_edit_misp(elem)
        {
            document.getElementById(elem.id+'edit').innerText = 'Edit instance';
            document.getElementById(elem.id+'delete').innerText = 'Delete instance';  
            document.getElementById(elem.id+'name').disabled = true;
            document.getElementById(elem.id+'insturl').disabled = true;
            document.getElementById(elem.id+'instkey').disabled = true;
            document.getElementById(elem.id+'limit').disabled = false;
            document.getElementById(elem.id+'page').disabled = false;
            document.getElementById(elem.id+'import').disabled = false;
            document.getElementById(elem.id+'check').style = "visibility: hidden; width: 0;";
        },
        import_misp_iocs(elem)
        {
            this.errors = [];
            this.imported = [];
            this.errorsInstance = []
            this.addedInstance = []

            axios.post(`/api/misp/get_iocs`, { data: { misp_id: elem.id, page: document.getElementById(elem.id+'page').value, limit: document.getElementById(elem.id+'limit').value } }, { headers: {'X-Token': this.jwt} })
            .then(response => {
                if(response.data.results.length>0){
                    console.log(response.data.results);
                    response.data.results.forEach(ioc => {
                    this.import_ioc(ioc["tag"], ioc["type"], ioc["tlp"], ioc["value"], elem.name + "_" + elem.id);
                    });
                }
                else
                {
                    console.log(response);
                }
            })
            .catch(err => (console.log(err)))
        },
        import_ioc: function(tag, type, tlp, ioc, source) {
            if (ioc != "" && ioc.slice(0,1)  != "#"){
                if("alert " != ioc.slice(0,6)) {
                    ioc = ioc.trim()
                    ioc = ioc.replace(" ", "")
                    ioc = ioc.replace("[", "")
                    ioc = ioc.replace("]", "")
                    ioc = ioc.replace("\\", "")
                    ioc = ioc.replace("(", "")
                    ioc = ioc.replace(")", "")
                }
                
                let finalioc = {ioc_tag: tag, ioc_type: type, ioc_tlp: tlp, ioc_value: ioc, ioc_source: "misp_" + source}

                axios.post(`/api/ioc/add_post`, { data: { ioc: finalioc } }, { headers: {'X-Token': this.jwt} })
                .then(response => {
                    if(response.data.status){
                        this.imported.push(response.data);
                    } else if (response.data.message){
                        this.errors.push(response.data);
                    }
                })
                .catch(err => (console.log(err)))
            }
        },
        get_misp_instances()
        {
            this.errorsInstance = []
            this.addedInstance = []
            this.mispInstances = []
            axios.get(`/api/misp/get_all`, { timeout: 10000, headers: {'X-Token': this.jwt} })
            .then(response => {
                console.log(response.data);
                if(response.data.results.length>0){
                    this.mispInstances = [].concat(this.mispInstances, response.data.results);
                }
            })
            .catch(err => (console.log(err)))
        },
        switch_tab: function(tab) {
            this.errors   = []
            this.errorsInstance = []
            this.addedInstance = []

            Object.keys(this.tabs).forEach(key => {
                if( key == tab ){
                    this.tabs[key] = true
                    if (key == "instances")
                    {
                        this.get_misp_instances();
                    }
                } else {
                    this.tabs[key] = false
                }
            });
        },
        get_jwt(){
            axios.get(`/api/get-token`, { timeout: 10000 })
                .then(response => {
                    if(response.data.token){
                        this.jwt = response.data.token
                    }
                })
            .catch(err => (console.log(err)))
        }
    },
    created: function() {
        this.get_jwt();
        this.get_misp_instances();
        if (this.mispInstances.length>0)
        {
            this.tabs["addmisp"] = false;
            this.tabs["instances"] = true;
        }
    }
}



</script>
