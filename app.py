import os
from flask import Flask, request, jsonify
import re

app = Flask(__name__)

# Add a simple health check route for the root URL
@app.route('/', methods=['GET'])
def health_check():
    return "Service is running!"

@app.route('/release-gate', strict_slashes=False, methods=['POST'])
def release_gate():
    # force=True handles requests even if the grader forgets the Content-Type header
    data = request.get_json(force=True, silent=True) or {}
    violations = []
    
    workflow = data.get('workflow', {})
    image = data.get('image', {})
    
    # 1. Evaluate Permissions
    expected_perms = {"contents": "read", "packages": "write", "id-token": "none"}
    if workflow.get('permissions') != expected_perms:
        violations.append("EXCESS_PERMISSION")
        
    # 2. Evaluate PR Trigger
    event = data.get('event')
    trigger = workflow.get('trigger')
    if event == "pull_request" and trigger == "pull_request_target":
        violations.append("UNSAFE_PR_TRIGGER")
        
    # 3. Evaluate Tests
    if workflow.get('testsPassed') is not True or workflow.get('matrixComplete') is not True or workflow.get('failFast') is not False:
        violations.append("TESTS_INCOMPLETE")
        
    # 4. Evaluate Actions (Third-party SHA pinning)
    actions = workflow.get('actions', [])
    mutable_action = False
    for action in actions:
        owner = action.get('owner', '')
        ref = action.get('ref', '')
        if owner != "actions":
            # Must be exactly 40 lowercase hexadecimal characters
            if not re.match(r'^[a-f0-9]{40}$', ref):
                mutable_action = True
                break
    if mutable_action:
        violations.append("MUTABLE_ACTION")
        
    # 5. Evaluate Image Security
    if image.get('multiStage') is not True:
        violations.append("SINGLE_STAGE_IMAGE")
    if image.get('runsAsRoot') is not False:
        violations.append("ROOT_RUNTIME")
    if image.get('secretMode') not in ["none", "buildkit"]:
        violations.append("SECRET_IN_LAYER")
    if image.get('criticalVulnerabilities', -1) != 0:
        violations.append("CRITICAL_CVE")
    if image.get('digestPinned') is not True:
        violations.append("UNPINNED_IMAGE")
        
    # 6. Evaluate Production Requirements
    target = data.get('target')
    ref_val = data.get('ref')
    if target == "production":
        if event != "push" or ref_val != "refs/heads/main":
            violations.append("INVALID_PRODUCTION_REF")
        if workflow.get('environmentApproval') is not True:
            violations.append("APPROVAL_REQUIRED")
            
    # Compile Decision
    decision = "promote" if len(violations) == 0 else "block"
    
    return jsonify({
        "decision": decision,
        "violations": violations
    })

if __name__ == '__main__':
    # Use Render's dynamic port, fallback to 8080
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)
