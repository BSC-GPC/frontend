<template>
  <div>
    <div id="componentsToolbar">
      <div class="btn-spaced-group" role="form">
        <b-button id="download-sbom-button" size="md" variant="outline-primary"
                @click="downloadSbom()"
                v-permission:or="[PERMISSIONS.VIEW_VULNERABILITY, PERMISSIONS.VULNERABILITY_ANALYSIS]">
          <span class="fa fa-download"></span> {{ $t('message.download_sbom') }}
        </b-button>
        <b-button id="download-audit-trail-button" size="md" variant="outline-primary"
                @click="downloadAuditTrail()"
                v-permission:or="[PERMISSIONS.VIEW_VULNERABILITY, PERMISSIONS.VULNERABILITY_ANALYSIS]">
          <span class="fa fa-download"></span> {{ $t('message.download_audit_trail') }}
        </b-button>
        <b-button id="download-kev-report-button" size="md" variant="outline-primary"
                @click="downloadKevReport()"
                v-permission:or="[PERMISSIONS.VIEW_VULNERABILITY, PERMISSIONS.VULNERABILITY_ANALYSIS]">
          <span class="fa fa-download"></span> {{ $t('message.download_kev_report') }}
        </b-button>
        <!-- <b-button id="download-dependency-tree-button" size="md" variant="outline-primary"
                @click="downloadDependencyTree()"
                v-permission:or="[PERMISSIONS.VIEW_VULNERABILITY, PERMISSIONS.VULNERABILITY_ANALYSIS]">
          <span class="fa fa-download"></span> {{ $t('message.download_dependency_tree') }}
        </b-button> -->
        <div style="margin-top: 1rem">
        <b-card>

          <h3>Get Vulnerabilities Within a Date Range</h3>
          <b-input-group-form-datepicker id="vulnerability-created-input" input-group-size="mb-3" v-model="startDate"
                                         lazy="true" required="false" feedback="false" autofocus="false" placeholder="YYYY-MM-DD"
                                         :label="$t('message.created')" :tooltip="this.$t('message.vulnerability_created_desc')"/>
          <b-input-group-form-datepicker id="vulnerability-published_input" input-group-size="mb-3" v-model="endDate"
                                         lazy="true" required="false" feedback="false" autofocus="false" placeholder="YYYY-MM-DD"
                                         :label="$t('message.published')" :tooltip="this.$t('message.vulnerability_published_desc')"/>
          <b-button id="download-vulnerabilities-in-range-button" size="md" variant="outline-primary"
              @click="downloadVulnerabilitiesInRange()"
              v-permission:or="[PERMISSIONS.VIEW_VULNERABILITY, PERMISSIONS.VULNERABILITY_ANALYSIS]">
            <span class="fa fa-download"></span> {{ $t('message.download_vulnerabilities_in_range') }}
          </b-button>
        </b-card>
      </div>
      </div>
    </div>
  </div>
</template>

<script>
import { Switch as cSwitch } from '@coreui/vue';
import $ from 'jquery';
import Vue from 'vue';
import xssFilters from "xss-filters";
import permissionsMixin from "../../../mixins/permissionsMixin";
import common from "../../../shared/common";
import * as XLSX from 'xlsx';
import BInputGroupFormDatepicker from "../../../forms/BInputGroupFormDatepicker";

export default {
    components: {
      cSwitch,
      BInputGroupFormDatepicker
    },
    data() {
      return {
        startDate: "",
        endDate: "",
    }},
    mixins: [permissionsMixin],
    props: {
      uuid: String,
      project: Object,
      tree: Array
    },
    methods: {
      initializeTooltips: function () {
        $('[data-toggle="tooltip"]').tooltip({
          trigger: "hover"
        });
      },
      
      // Download this project's SBOM in excel format
      downloadSbom: async function () {
        let components = await this.getComponents();
        let vulnerabilities = await this.getVulnerabilities();

        let book = this.createExcelBook();
        book = this.addExcelSheet(components, book, "SBOM Components");
        book = this.addExcelSheet(vulnerabilities, book, "SBOM Vulnerabilities");

        this.downloadExcelBook(book, this.project.name, this.project.version || "", "SBOM"); 
      },

      // Download this project's audit trail in excel format
      downloadAuditTrail: async function () {
        let auditTrail = await this.getAllAuditTrails();

        let book = this.createExcelBook();
        book = this.addExcelSheet(auditTrail, book, "Audit Trail");

        this.downloadExcelBook(book, this.project.name, this.project.version || "", "Audit Trail"); 
      },

      // Download this project's KEV report in excel format
      downloadKevReport: async function () {
        let kevReport = await this.getVulnerabilitiesInKev();

        let book = this.createExcelBook();
        book = this.addExcelSheet(kevReport, book, "KEV Report");

        this.downloadExcelBook(book, this.project.name, this.project.version || "", "KEV"); 
      },

      // Download this project's dependency tree in excel format (NOTE: STILL IN DEVELOPMENT)
      downloadDependencyTree: async function () {
        await this.getDependencyGraph();
        let book = this.createExcelBook();
        book = this.addExcelSheet(this.tree, book, "Dependency Tree");

        this.downloadExcelBook(book, this.project.name, this.project.version || "", "Dependency Tree"); 
      },

      // Download this project's vulnerabilities within a date range in excel format
      downloadVulnerabilitiesInRange: async function () {
        let vulnerabilities = await this.getVulnerabilitiesInRange(this.startDate, this.endDate);
        let formattedVulnerabilities = this.formatVulnerabilitiesInRange(vulnerabilities);

        let book = this.createExcelBook();
        book = this.addExcelSheet(formattedVulnerabilities, book, "Vulnerabilities In Range");

        this.downloadExcelBook(book, this.project.name, this.project.version || "", "Vulnerabilities in Range"); 
      },

      // Return this project's SBOM components in excel format
      getComponents: async function () {
        let url = `${this.$api.BASE_URL}/${this.$api.URL_COMPONENT}/project/${this.uuid}`;
        return this.axios.request({
          url: url,
          method: 'get'
        }).then((response) => {
          // Excel Format
          let componentData = [["Component Name", "Component Version", "Classifier", "CPE", "PURL", "License Name", "SPDX License ID", 
              "License Group", "Total # of Vulnerabilities", "# of Low Vulnerabilities", "# of Medium Vulnerabilities", 
              "# of High Vulnerabilities", "# of Critical Vulnerabilities"]];

          let components = response.data;

          // Loop through all SBOM components and format them
          for(let i = 0; i < components.length; i++){
            let licenseName = "";
            let licenseID = "";
            let licenseGroups = "";

            componentData.push([components[i].name, components[i].version, components[i].classifier, components[i].cpe, components[i].purl, 
                licenseName, licenseID, licenseGroups, components[i].metrics.vulnerabilities, components[i].metrics.low, components[i].metrics.medium, 
                components[i].metrics.high, components[i].metrics.critical
            ]);
          }
          return componentData;
        })
      },

      // Return this project's SBOM vulnerabilities in excel format
      getVulnerabilities: function () {
        let url = `${this.$api.BASE_URL}/${this.$api.URL_VULNERABILITY}/project/${this.uuid}`;
        return this.axios.request({
          url: url,
          method: 'get'
        }).then((response) => {
          // Excel Format
          let vulnerabilityData = [["Vulnerability ID", "Source", "Component with Vulnerability", "Severity Level", "Description", 
              "CVSS V3 Vector", "CVSS V3 Base Score", "CVSS V2 Base Score", "EPSS Score", "Date Published", "Date Updated"
          ]];

          let vulnerabilities = response.data;

          // Loop through all SBOM vulnerabilities and format them
          for(let i = 0; i < vulnerabilities.length; i++) {
            vulnerabilityData.push([vulnerabilities[i].vulnId, vulnerabilities[i].source, vulnerabilities[i].components[0].name, 
                vulnerabilities[i].severity, vulnerabilities[i].description, vulnerabilities[i].cvssV3Vector, vulnerabilities[i].cvssV3BaseScore, 
                vulnerabilities[i].cvssV2BaseScore, vulnerabilities[i].epssScore, vulnerabilities[i].published, vulnerabilities[i].updated
            ]);
          }
          return vulnerabilityData;
        })        
      },

      // Return this project's vulnerabilties within a date range
      getVulnerabilitiesInRange: function (startDate, endDate) {
        let url = `${this.$api.BASE_URL}/${this.$api.URL_VULNERABILITY}/project/${this.uuid}`;        
        return this.axios.request({
          url: url,
          method: 'get'
        }).then((response) => {
          let vulnerabilities = response.data;
          let vulnerabilitiesInRange = [];

          // Loop through each vulnerability and check if it's in the date range
          for(let i = 0; i < vulnerabilities.length; i++){
            if(vulnerabilities[i].updated <= endDate && vulnerabilities[i].updated >= startDate){
              vulnerabilitiesInRange.push(vulnerabilities[i]);
            }
          }
          return vulnerabilitiesInRange;
        })
      },

      // Return vulnerabilities within range in excel format
      formatVulnerabilitiesInRange: function (vulnerabilities) {
        let dataToExport = [["Date BSC Became Aware of Vulnerability", "Quarter \nNote: Optional but allows easily filtering", 
            "Analysis Owner \nNote: Optional but facilitates work on large teams", 
            "Product Affected \nNote: Optional but facilitates work when combined report used for related products or product families",
            "Product Version \nNote: Optional but facilitates work when combined report used for related products or product families",
            "Component (e.g. OTSS SW) with Vulnerability", "Component (e.g. OTSS SW) Version", 
            "Source Which Identified Cybersecurity Vulnerability \nNote: Optional but facilitates understanding how the team became aware of the vulnerability",
            "Vulnerability Identifier (e.g. CVE Number)", "Vulnerability Summary \nNote: Optional but facilitates quick understanding of vulnerability",
            "CVSS 3.0 Score \nNote: Optional but CVSS is commonly referenced and used to determine the risk from a vulnerability"]];

        for(let i = 0; i < vulnerabilities.length; i++){
            dataToExport.push([vulnerabilities[i].updated, "", "", this.project.name, this.project.version,
                            vulnerabilities[i].components[0].name, vulnerabilities[i].components[0].version,
                            vulnerabilities[i].source, vulnerabilities[i].vulnId, vulnerabilities[i].description, vulnerabilities[i].cvssV3BaseScore]);
        }
        return dataToExport;
      },

      // Return audit trail for a specific vulnerability
      getAuditTrail: async function (compUUID, vulnUUID) { // for a specific vuln, in a specific component, in a specific project
        let url = `${this.$api.BASE_URL}/${this.$api.URL_ANALYSIS}?project=${this.uuid}&component=${compUUID}&vulnerability=${vulnUUID}`;
        return this.axios.request({
          url: url,
          method: 'get'
        });
      },

      // Return project's audit trail of all vulnerabilities in excel format
      getAllAuditTrails: async function () {
        let vulnerabilities = (await this.getFindings()).data;

        // The data to export to excel - contains the audit trail of each vulnerability
        let dataToExport = [["Vulnerability ID", "Component Name", "Component Version", "Analysis State", 
                            "Analysis Justification", "Analysis Response", "Analysis Details", 
                            "Analysis Comments - History", "Is Suppressed?"]];

        // Loop through each vulnerability & add its audit trail to the data 
        for(let i = 0; i < vulnerabilities.length; i++) {
          let parsedComments = [];
          let auditDetails = [];

          // Check if an audit trail exists for this vulnerabiltiy
          if(vulnerabilities[i].analysis.state){
            auditDetails = (await this.getAuditTrail(vulnerabilities[i].component.uuid, vulnerabilities[i].vulnerability.uuid)).data;
            parsedComments = this.parseComments(auditDetails.analysisComments);
          }

          // Create excel row of data with audit trail info
          let dataRow = [vulnerabilities[i].vulnerability.vulnId, vulnerabilities[i].component.name, vulnerabilities[i].component.version,
                      auditDetails.analysisState, auditDetails.analysisJustification, auditDetails.analysisResponse,
                      auditDetails.analysisDetails, parsedComments, auditDetails.isSuppressed];
          dataToExport.push(dataRow);
        }
        return dataToExport;
      },

      // Return whether this project is affected by a specific vulnerability
      projectAffectedByVulnerability: async function (vulnUUID) {
        let url = `${this.$api.BASE_URL}/${this.$api.URL_VULNERABILITY}/source/NVD/vuln/${vulnUUID}/projects`;
        return this.axios.request({
          url: url,
          method: 'get'
        }).then((response) => {
          let projects = response.data;

          // Loop through the projects affected by this vulnerability & see if any match this project
          for(let i = 0; i < projects.length; i++) {
            if(this.uuid == projects[i].uuid){
              return true;
            }
          }
          return false;
        });
      },

      // Return the KEV catalog (CISA)
      getKevCatalog: async function () {
        // FIX ???
        let cisaUrl = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
        let dogUrl = 'https://dogapi.dog/api/facts';
        let workingUrl = "http://localhost:3000/kev";
        let testUrl = `${this.$api.BASE_URL}/kev`;

        return this.axios.request({
          url: testUrl,
          method: 'get'
        });
      },
      
      // Return project's KEV vulnerabilities in excel format
      getVulnerabilitiesInKev: async function () {
        let vulnerabilities = (await this.getKevCatalog()).data.vulnerabilities;

        // Excel format
        let dataToExport = [["CVE ID", "Vulnerability Name", "Vendor Project", "Product", 
                            "Description", "Required Action", "Known Ransomeware Campaign Use", 
                            "Date Added", "Due Date", "Notes"]];

        // Loop through each vulnerability in the KEV catalog & check if it affects this project
        for(let i = 0; i < vulnerabilities.length; i++){ 
          let affected = await this.projectAffectedByVulnerability(vulnerabilities[i].cveID);
          if(affected){
            // Create excel row of data with KEV info
            let dataRow = [vulnerabilities[i].cveID, vulnerabilities[i].vulnerabilityName, vulnerabilities[i].vendorProject,
                          vulnerabilities[i].product, vulnerabilities[i].shortDescription, vulnerabilities[i].requiredAction,
                          vulnerabilities[i].knownRansomwareCampaignUse, vulnerabilities[i].dateAdded, 
                          vulnerabilities[i].dueDate, vulnerabilities[i].notes];
            dataToExport.push(dataRow);
          }
        }
        return dataToExport;
      },

      // Return all findings for a specific project (for audit trail information)
      getFindings: function () {
        let url = `${this.$api.BASE_URL}/${this.$api.URL_FINDING}/project/${this.uuid}`;
        return this.axios.request({
          url: url,
          method: 'get'
        })
      },

      // Parse the comments array in a vulnerability's audit trail 
      parseComments: function (comments){
        let parsedComments = "";
        // Reformat the comments if there are any
        console.log(comments)
        if(comments !== undefined){
            for(let i = 0; i < comments.length; i++){
                parsedComments += comments[i].commenter + ": " + comments[i].comment + "   \n"
            }
        }
        console.log("parser com: ", parsedComments)
        return parsedComments;
      },

      // Get the entire dependency tree/graph for a project
      getDependencyGraph: async function () {
        let url = `${this.$api.BASE_URL}/${this.$api.URL_BOM}/cyclonedx/project/${this.uuid}`;
        return this.axios.request({
          url: url,
          method: 'get'
        }).then((response) => {
          // Get all components and their dependencies
          let components = response.data.components;
          let dependencies = response.data.dependencies;

          // Map each component's ref id to its names
          let mapNames = new Map();
          for(let i = 0; i < components.length; i++){        
            mapNames.set(components[i]["bom-ref"], components[i].name);
          }

          // Map each component's ref id to its dependencies
          let mapDependencies = new Map();
          for(let i = 1; i < dependencies.length; i++){
            mapDependencies.set(dependencies[i].ref, dependencies[i].dependsOn);
          }

          this.tree = []

          // Create tree structure of the project's dependencies
          for(let i = 1; i < dependencies.length; i++){
            let path = [];
            path.push(mapNames.get(dependencies[i].ref));
            this.getDeps(path, dependencies[i].dependsOn, mapDependencies, mapNames);
          }
        })
      },

      // Recursively loop through project dependencies and add them to the tree
     getDeps: function (path, dependencies, mapDependencies, mapNames) {
        // Global var not working correctly ???
        // Base case: no dependencies for this component
        if(dependencies.length == 0){
          this.tree.push(path);
          return;
        }

        // Recursive case: component has dependencies (loop through each dep)
        for(let i = 0; i < dependencies.length; i++){
          // Create a new branch/path off the existing one
          let nextPath = path.slice();
          nextPath.push(" --> ")
          nextPath.push(mapNames.get(dependencies[i]));

          // Get dependencies of this dependency
          this.getDeps(nextPath, mapDependencies.get(dependencies[i]), mapDependencies, mapNames);
        }
      },

      // Create a new excel workbook
      createExcelBook: function() {
        return XLSX.utils.book_new();
      },

      // Add a new excel sheet to an existing workbook
      addExcelSheet: function (data, book, sheetName) {
        let sheet = XLSX.utils.aoa_to_sheet(data);
        book.SheetNames.push(sheetName);
        book.Sheets[sheetName] = sheet;
        return book;
      },

      // Download an excel workbook
      downloadExcelBook: function (book, projectName, projectVersion, reportType) {
        XLSX.writeFile(book, projectName+" "+projectVersion+" "+reportType+".xlsx");
      }
    },
  };
</script>
