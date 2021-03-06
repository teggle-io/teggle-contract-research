## Project Description
Teggle intends to be the very first truly decentralised, censorship resistant and private social network. We intend to create a privacy by default, intuitive to use, performant and mass-adoptable platform.

## Problem / Solution
All the existing blockchain based social networks may solve the issue of censorship, but they do not solve privacy. Everything posted is public by default, with no means to make it otherwise. With the advent of AI, this becomes a very big problem as it means our information can be mined and used against us to create consent.

There are some solutions out there that address privacy, like Zion, but most of them lack one or more aspects of what is needed to create "the next Facebook". In the case of Zion, it also lacks being truly decentralised as each "group" needs to establish their own node and each group can not see the other.

What we are proposing is to develop a solution that can be seen in the eyes of the people as a true replacement for the likes of the current "big tech" offerings. Ideally, being seen as the next evolution, with no compromises.

## Detailed product description
A significant amount of time has already been spent researching the best ways to achieve the solution we want. Along the way, we encountered some obstacles and have developed innovative workarounds. A lot of detail has already been added to our "Purple Paper", so this section will focus on summarising what is important and also add details missing from the purple paper where necessary. For more information, see the draft of our purple paper (white paper): https://teggle.com/purplepaper/.

### Objectives

Teggle aims to be seen as a premiere product and geared towards mass-adoption. Featuring sleek UI design and advanced / novel features. To achieve mass adoption we also need to overcome some of the current problems with "web3" technologies, people aren't going to want to sign a transaction to like a post for example. The majority of these are solved with our novel Layer 2 solution.

### Layer 2

By combining transactions together you can both increase throughput, reduce network congestion as well as reduce the cost per transaction. You also don't have to force people to sign transactions and can even offer freemium services.

#### Hub

A hub will collect transactions from multiple users and submit them in batches to Omnibus. Anyone will be able to run a hub as the transactions they are given are encrypted using a Layer 2 session (see the paper for details). Someone who runs a hub can make money from submitting the transactions to Omnibus; In exchange for paying the transaction fees (in SCRT) they will be given some Teggle native tokens (yet to be given a denom).

#### Omnibus

Omnibus is both the system responsible for combining the layer 2 transactions, but also an engine capable of running upgradable "cortexes" (or cores). Smart contracts on the Secret Network are not upgradable and likely never will be due to the limitations of how the encryption works (the software hash is part of the key used to encrypt them). So even though it wasn't part of the original plan to have these "cortexes" it was required as we needed to be able to upgrade our software. The only other option is to migrate data to the new contract which is impossible for something like a social network. Nonetheless, the result is a standalone project that we are sure community will love and many projects will use.

#### Indexer

This was one of the most mind-boggling pieces of the research. To run a social network, you cannot query the blockchain for information. What you really need is a graph database, or at the very least a relational database. We don't have to see the content, but the metadata, the connections between people in order to create an index. The primary goal would be to not expose this information either, no one should know who your friends are. The best solution early on was to just make this part private, at least it wouldn't be open to the world. Thankfully, a solution came at the last minute and after a considerable amount of research it appears to be a viable option. The indexer will also run inside an SGX enclave, much like the Secret Network contracts do! If you're curious to know more, read the paper ("Indexer & Search").

## Go-to-Market plan
Our intention for this milestone is to build out a "Minimum Demonstrable Product" (MDP) and use it as a means to seek further funding through an IDO/ICO. We will require further assistance from either Secret Network or it's investors at that stage, but hope that by then the project is exciting enough there will be a lot of interest.

Thankfully the products of this milestone will be several open source components that the Secret Network community will be able to use right away. Additionally, this milestone also intends to build enough features to also facilitate the IDO (i.e. Tokenomics and Governance).

Once we are ready to go to market, our plan will look something like this: We'll recruit marketing specialists and community managers to devise a set of game plans. At first, we will target communities that are most likely to be looking for privacy focused solutions. Next, we'll promote our slick experience to other key demographics, selling it as the logical evolution of social media. All the while not looking to target any group specifically, but always trying to obtain a broad range of users. We'll also start grass roots groups who's sole responsibility will be to see Teggle succeed and to drive adoption. We will enable this by offering a referral based system, they will be given a certain percentage of the users transaction fees (either for life, or for a certain period of time).

A huge part of acquiring new users will be availability of content. So one of our primary focuses early on will be to attract content creators to the platform. Ideally looking to acquire a range of content and having well known content creators use our platform in addition to to their current ones (at least to begin with). This will be achieved by finding creators who believe in our mission as well as through incentive programs.

## Value capture for Secret Network ecosystem
The Teggle project will bring numerous benefits to the Secret Network, and it's community:
* First full-featured "Social Network" to be built on Secret Network. Aimed at mass adoption, by proxy, should massively increase network awareness and utilization.
* First "Layer 2" technology to be built exclusively on Secret Network. For now, this will be exclusive to Teggle transactions but as more projects use Omnibus it may be possible to aggregate cross-contract via "smart hubs". The layer 2 technology also means much more efficient operations, so Teggle will place less strain on the network. Throughput can be upwards of 1000 times more than the Layer 1 network by itself.
* First "Upgradable Contracts" on Secret Network: Omnibus - Framework for building composable and upgradable smart contracts on Secret Network.
* First "Secure Indexer" running on Secret Network. The research done to create this can be used by other teams with significantly less effort. It is our vision to eventually create a generic indexing platform that Secret Network projects can use to create true "web3" applications.
* Numerous other by-products of developing a project of this scope, including:
  * secret-client-rs: SGX compatible Secret Network rust client (required for hub and indexer).
  * teggle-rhai-module-resolver-zip: Rhai module file resolver (already finished, required for Omnibus).
  * patches created for rhai which increases performance by 60% (already submitted, required for Omnibus).
  * paves the way to provide more generic indexing services for Secret Network, running Omnibus instances both inside Secret Smart contracts and also inside indexers.

## Team members
* David Radunz (github: @rhomber, discord: Lyran Sage#1988)

### Consultants & Guidance
* Stephen Chung (github: @schungx) - rhai primary contributor. (rhai coaching / help / modifications)
* Assaf Morami (github: @assafmo) - Secret Labs. (coaching / guidance)
* Reuven Podmazo (github: @reuvenpo) - Secret Labs. (coaching / guidance)

## Team Website
* http://teggle.com/ - Teggle (project homepage, the app will be hosted on teggle.io)
* http://vimturian.ltd/ - Vimturian Ltd (David's consulting company)

## Team's experience
* David has over 20 years of experience.
  * He has worked with some of the most renowned IT companies in Australia.
  * The roles he has held include:
    * CTO / VP of Engineering / Project Manager
    * Senior Architect / Solutions Architect
    * Senior (Full-Stack) Software Engineer
    * Senior Systems & Networking Engineer

## Team Code Repos
The majority of the work David has done has been private, however in the last month he has written a significant amount of code related to the Teggle project (and researching / proving certain requirements). Should you require it, David can provide references in lue of publicly committed code.

* https://github.com/teggle-io (Teggle repo, of note: teggle-omnibus, teggle-contract-research and teggle-index-research)
* https://github.com/rhomber (David's github, mostly forks)

## Team LinkedIn Profiles
* https://www.linkedin.com/in/david-radunz/

## Development Roadmap
We will require ~11 months (48 weeks) to complete this milestone of the project. We intend to have 1 developer (David) full-time (60 hours a week @ $100/hr), at a total cost of $288,000.

The project has been planned around 4 week "sprints" and is documented here: https://github.com/orgs/teggle-io/projects/1/views/1

Sprints (4 weeks @ 60 hrs a week, 240 hrs total):
* Sprint 1 - Omnibus (improving upon what has already been built).
* Sprint 2 - Omnibus (release Omnibus to Secret Network community).
* Sprint 3 - Omnibus enhancements, Create "secret-client-rs" (SN rust client), Build hub.
* Sprint 4 - Indexer, research and build.
* Sprint 5 - Create Teggle web app (UI), Create profile feature.
* Sprint 6 - Content storage, Omnibus enhancements, Notifications feature, View profile feature.
* Sprint 7 - "Add Friend" feature, Create post feature.
* Sprint 8 - View feed feature, Reactions / likes feature.
* Sprint 9 - Reactions / likes feature continued, Post attachments (i.e. gallery).
* Sprint 10 - Comments feature, react to comment feature.
* Sprint 11 - Tokenomics research & implementation.
* Sprint 12 - Governance research & implementation.

Ideally, we can receive payments in 4 disbursements:
* At the beginning of the grant.
* At the start of Sprint 4.
* At the start of Sprint 7.
* At the start of Sprint 10 (or at the end if desired).

We would be willing to consider part payment in SCRTs, up to 25% (paid at the equivalent USD exchange rate for each disbursement).
